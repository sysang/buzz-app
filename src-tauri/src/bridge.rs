//! The daemon bridge WebSocket endpoint (WDA-S-03.1): the wire vocabulary
//! the browser shim (WDA-S-04) and the transport-aware host adapter
//! (WDA-S-03.2, WDA-WI-09) speak over the daemon's loopback listener.
//!
//! Scope of this module: WDA-WI-08's endpoint plus WDA-WI-09 part A's
//! two-command adapter proof slice.
//!
//! - the `/bridge` route on the same loopback listener (never a second
//!   listener or port). RFC 6455 requires the `101` to carry
//!   `Connection: Upgrade`; the shared listener's accepted
//!   `.keep_alive(false)` discipline makes hyper's encoder force
//!   `Connection: close` on every response (verified on the raw wire), which
//!   no WebSocket client accepts. The bridge therefore takes over `/bridge`
//!   upgrades before hyper parses the request: a bounded, strictly gated
//!   non-consuming head peek in the connection task hands the socket to a
//!   manual RFC 6455 handshake (`Sec-WebSocket-Accept` derived from the
//!   client nonce), and every other request reaches hyper byte-identically.
//! - auth-first ordering and auth-frame shape/generation validation; the
//!   token and generation are recorded opaquely and connection-scoped.
//! - invoke framing: JSON or `kind:"raw"` bodies plus optional preserved
//!   headers; a `kind:"raw"` invoke takes exactly one following binary frame.
//! - server frame encoding: `invoke_ok` / `invoke_err` JSON, callback
//!   envelopes (`{index,message}` / `{index,end:true}`, `message:null` as the
//!   reserved raw-ref marker), and binary `0x01` response / `0x02` channel
//!   delivery frames (1-byte tag + 8-byte little-endian ID + bytes).
//! - the ID contract: every wire ID is an unsigned 53-bit (`Number.MAX_SAFE_INTEGER`)
//!   browser-safe integer; bit 52 marks the callback namespace. Invoke IDs are
//!   `[0, 2^52)`; server-allocated callback IDs and `0x02` IDs are
//!   `[2^52, 2^53)`; `0x01` response IDs use the invoke namespace. Namespaces
//!   are disjoint.
//! - connection-scoped generation state (from the auth frame); it is never
//!   written back to the wire.
//! - upgrade permit accounting: the upgrade moves the connection's admission
//!   permit into the session; exactly one permit stays held until the
//!   socket closes. Nothing is acquired twice.
//!
//! This module dispatches only the State-based `pairing_status` and
//! AppHandle-based `identity_legacy_available` proof commands through the
//! production host adapter. The listener's shared exact Host and supplied
//! Origin gate runs before upgrade admission; the WS-specific mandatory
//! Origin rule and auth-deadline duration are WI-11 contract decisions still
//! pending. First-frame auth is checked against the same per-start bearer
//! stored by `Policy`; failed auth closes before takeover or dispatch.
use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{header, Method, Request, Response, StatusCode, Version};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{handshake::derive_accept_key, Message};
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::bridge_adapter::{
    AdapterResponse, CommandInput, ConnectionOwner, GenerationArbiter, InvocationAdapter,
    SessionContext,
};
use crate::web::{single_header, with_csp, Policy};

/// The largest unsigned 53-bit integer — the browser-safe ID ceiling
/// (`Number.MAX_SAFE_INTEGER`). Every wire ID is in `0..=MAX_WIRE_ID`.
pub(crate) const MAX_WIRE_ID: u64 = (1 << 53) - 1;
/// Bit 52 of the wire ID space marks the callback namespace.
const NS_BIT: u64 = 1 << 52;
/// Largest invoke-namespace ID.
pub(crate) const INVOKE_NAMESPACE_MAX: u64 = NS_BIT - 1;
/// Smallest callback-namespace ID.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) const CALLBACK_NAMESPACE_MIN: u64 = NS_BIT;

/// In-flight invokes per connection. Overflow retires the connection — the
/// bounded-listener discipline of WDA-S-02.4, where overflow is a visible
/// failure, not a silent drop.
pub(crate) const MAX_PENDING_INVOKES: usize = 256;

#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
fn is_invoke_id(id: u64) -> bool {
    id <= INVOKE_NAMESPACE_MAX
}

#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn is_callback_id(id: u64) -> bool {
    (CALLBACK_NAMESPACE_MIN..=MAX_WIRE_ID).contains(&id)
}

/// Extracts a wire ID from a JSON value. `serde_json` yields exact integers
/// for everything in the browser-safe range, so anything fractional,
/// negative or beyond `MAX_WIRE_ID` fails here.
fn wire_id(value: &Value) -> Option<u64> {
    let id = value.as_u64()?;
    (id <= MAX_WIRE_ID).then_some(id)
}

/// A bridge frame that failed validation. The connection closes; nothing is
/// dispatched. The payload is a stable reason tag for logging/debugging,
/// not a wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireError(pub(crate) &'static str);

/// A decoded client frame.
#[derive(Debug, PartialEq)]
pub(crate) enum Frame {
    /// `{"type":"auth","token":<string>,"generation":<n>}` — must be first.
    /// The raw request body of a `kind:"raw"` invoke arrives as the next
    /// binary frame and is handled at the session layer, not by this parser.
    Auth { token: String, generation: u64 },
    /// `{"type":"invoke",...}`.
    Invoke(Invoke),
}

/// A decoded `{"type":"invoke",...}` frame.
#[derive(Debug, PartialEq)]
pub(crate) struct Invoke {
    pub(crate) id: u64,
    pub(crate) cmd: String,
    pub(crate) body: InvokeBody,
    /// The application headers the command receives, preserved as parsed.
    pub(crate) headers: Option<serde_json::Map<String, Value>>,
}

/// The request body carrier of an invoke.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum InvokeBody {
    /// `kind:"json"` — the value arrives inline; it may be any JSON value.
    Json(Value),
    /// `kind:"raw"` — the value arrives in the following binary frame.
    Raw,
}

/// Every object-shaped frame must carry exactly its declared members.
fn exact_keys(object: &serde_json::Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

/// Parses and validates one client text frame. Frame *types* outside the
/// vocabulary all produce `WireError`; callers close the connection.
pub(crate) fn parse_frame(text: &str) -> Result<Frame, WireError> {
    let value: Value = serde_json::from_str(text).map_err(|_| WireError("malformed JSON frame"))?;
    let object = value
        .as_object()
        .ok_or(WireError("frame is not a JSON object"))?;
    let frame_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(WireError("frame type is missing or not a string"))?;
    match frame_type {
        "auth" => parse_auth(object),
        "invoke" => parse_invoke(object),
        _ => Err(WireError("unknown frame type")),
    }
}

fn parse_auth(object: &serde_json::Map<String, Value>) -> Result<Frame, WireError> {
    if !exact_keys(object, &["type", "token", "generation"]) {
        return Err(WireError("auth frame shape"));
    }
    let token = object["token"]
        .as_str()
        .ok_or(WireError("auth token is not a string"))?
        .to_owned();
    let generation =
        wire_id(&object["generation"]).ok_or(WireError("auth generation out of range"))?;
    Ok(Frame::Auth { token, generation })
}

fn parse_invoke(object: &serde_json::Map<String, Value>) -> Result<Frame, WireError> {
    let keys: &[&str] = if object.contains_key("headers") {
        &["type", "id", "cmd", "body", "headers"]
    } else {
        &["type", "id", "cmd", "body"]
    };
    if !exact_keys(object, keys) {
        return Err(WireError("invoke frame shape"));
    }
    let id = wire_id(&object["id"]).ok_or(WireError("invoke id out of range"))?;
    if !is_invoke_id(id) {
        return Err(WireError("invoke id outside the invoke namespace"));
    }
    let cmd = object["cmd"]
        .as_str()
        .ok_or(WireError("cmd is not a string"))?
        .to_owned();
    if cmd.is_empty() {
        return Err(WireError("cmd is empty"));
    }
    let body_object = object["body"]
        .as_object()
        .ok_or(WireError("invoke body is not an object"))?;
    let body = parse_body(body_object)?;
    let headers = match object.get("headers") {
        None => None,
        Some(Value::Object(map)) => {
            if map.values().any(|value| !value.is_string()) {
                return Err(WireError("header value is not a string"));
            }
            Some(map.clone())
        }
        Some(_) => return Err(WireError("headers is not an object")),
    };
    Ok(Frame::Invoke(Invoke {
        id,
        cmd,
        body,
        headers,
    }))
}

fn parse_body(object: &serde_json::Map<String, Value>) -> Result<InvokeBody, WireError> {
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(WireError("invoke body kind is missing or not a string"))?;
    match kind {
        "json" => {
            if !exact_keys(object, &["kind", "value"]) {
                return Err(WireError("json invoke body shape"));
            }
            Ok(InvokeBody::Json(object["value"].clone()))
        }
        "raw" => {
            if !exact_keys(object, &["kind"]) {
                return Err(WireError("raw invoke body shape"));
            }
            Ok(InvokeBody::Raw)
        }
        _ => Err(WireError("unknown invoke body kind")),
    }
}

// --- Server frame encoding -------------------------------------------------

#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
fn check_index(index: u64) -> Result<(), WireError> {
    if index <= MAX_WIRE_ID {
        Ok(())
    } else {
        Err(WireError("callback index out of range"))
    }
}

/// S→C `{"type":"invoke_ok","id":<n>,"payload":<json-value>}`.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn encode_invoke_ok(id: u64, payload: &Value) -> Result<String, WireError> {
    if !is_invoke_id(id) {
        return Err(WireError("response id outside the invoke namespace"));
    }
    Ok(serde_json::json!({ "type": "invoke_ok", "id": id, "payload": payload }).to_string())
}

/// S→C `{"type":"invoke_err","id":<n>,"error":<json-value>}`.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn encode_invoke_err(id: u64, error: &Value) -> Result<String, WireError> {
    if !is_invoke_id(id) {
        return Err(WireError("response id outside the invoke namespace"));
    }
    Ok(serde_json::json!({ "type": "invoke_err", "id": id, "error": error }).to_string())
}

/// S→C `{"type":"callback","id":<n>,"envelope":{"index":<n>,"message":<json>}}`.
/// `message` is reserved as non-null for JSON deliveries; `null` is the
/// raw-ref marker and is rejected here.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn encode_callback_json(
    id: u64,
    index: u64,
    message: &Value,
) -> Result<String, WireError> {
    if !is_callback_id(id) {
        return Err(WireError("callback id outside the callback namespace"));
    }
    check_index(index)?;
    if message.is_null() {
        return Err(WireError(
            "null is reserved as the raw-ref marker; use encode_callback_raw",
        ));
    }
    Ok(serde_json::json!({
        "type": "callback",
        "id": id,
        "envelope": { "index": index, "message": message },
    })
    .to_string())
}

/// S→C callback envelope with the raw-ref marker:
/// `{"index":<n>,"message":null}`. The payload itself arrives as the `0x02`
/// binary frame whose 8-byte little-endian ID is this callback's ID.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn encode_callback_raw(id: u64, index: u64) -> Result<String, WireError> {
    if !is_callback_id(id) {
        return Err(WireError("callback id outside the callback namespace"));
    }
    check_index(index)?;
    Ok(serde_json::json!({
        "type": "callback",
        "id": id,
        "envelope": { "index": index, "message": Value::Null },
    })
    .to_string())
}

/// S→C termination envelope `{"index":<n>,"end":true}` with callback release.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn encode_callback_end(id: u64, index: u64) -> Result<String, WireError> {
    if !is_callback_id(id) {
        return Err(WireError("callback id outside the callback namespace"));
    }
    check_index(index)?;
    Ok(serde_json::json!({
        "type": "callback",
        "id": id,
        "envelope": { "index": index, "end": true },
    })
    .to_string())
}

#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
fn binary(tag: u8, id: u64, bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + bytes.len());
    frame.push(tag);
    frame.extend_from_slice(&id.to_le_bytes());
    frame.extend_from_slice(bytes);
    frame
}

/// S→C binary `0x01` response: tag + 8-byte little-endian invoke ID + bytes.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn encode_binary_response(id: u64, bytes: &[u8]) -> Result<Vec<u8>, WireError> {
    if !is_invoke_id(id) {
        return Err(WireError("response id outside the invoke namespace"));
    }
    Ok(binary(0x01, id, bytes))
}

/// S→C binary `0x02` channel delivery: tag + 8-byte little-endian callback
/// ID + bytes.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn encode_binary_channel(id: u64, bytes: &[u8]) -> Result<Vec<u8>, WireError> {
    if !is_callback_id(id) {
        return Err(WireError("channel id outside the callback namespace"));
    }
    Ok(binary(0x02, id, bytes))
}

/// A decoded S→C binary frame.
#[derive(Debug, PartialEq)]
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) enum BinaryFrame<'a> {
    Response { id: u64, bytes: &'a [u8] },
    Channel { id: u64, bytes: &'a [u8] },
}

/// Decodes one S→C binary frame; the tag picks the namespace the ID must
/// live in.
#[allow(dead_code)] // Consumed by WDA-WI-09/WDA-WI-10 (adapter and push delivery); exercised by the codec tests.
pub(crate) fn decode_binary_frame(frame: &[u8]) -> Result<BinaryFrame<'_>, WireError> {
    if frame.len() < 9 {
        return Err(WireError("binary frame is too short"));
    }
    let id = u64::from_le_bytes(frame[1..9].try_into().expect("slice of 8 bytes"));
    match frame[0] {
        0x01 => {
            if !is_invoke_id(id) {
                return Err(WireError("response id outside the invoke namespace"));
            }
            Ok(BinaryFrame::Response {
                id,
                bytes: &frame[9..],
            })
        }
        0x02 => {
            if !is_callback_id(id) {
                return Err(WireError("channel id outside the callback namespace"));
            }
            Ok(BinaryFrame::Channel {
                id,
                bytes: &frame[9..],
            })
        }
        _ => Err(WireError("unknown binary frame tag")),
    }
}

// --- The upgrade -----------------------------------------------------------

const CLOSE_POLICY: CloseCode = CloseCode::Policy;
const AUTH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
/// Private-use auth rejection code; S-03.4 requires closing but defines no
/// numeric close code or wire reason.
const CLOSE_AUTHENTICATION_FAILED: CloseCode = CloseCode::Library(4003);

fn ws_config() -> WebSocketConfig {
    // Bounded exactly like the host's existing native relay socket
    // (`federated_identity::socket`): 1 MiB message and frame caps — well
    // above the 64 KiB upload chunks the frontend sends, and strictly
    // smaller than the crate default (64 MiB / 16 MiB). `max_write_buffer_size`
    // keeps the crate default (it fills only under write failure), matching
    // the relay socket.
    WebSocketConfig::default()
        .max_message_size(Some(1024 * 1024))
        .max_frame_size(Some(1024 * 1024))
}

fn bare(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn bare_with_header(
    status: StatusCode,
    body: &'static str,
    name: &str,
    value: &str,
) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(name, value)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn header_tokens(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

/// Validates the RFC 6455 upgrade request and, on success, returns the
/// `Sec-WebSocket-Accept` value to serve. Failure is a plain HTTP response.
fn accept_key(request: &Request<Incoming>) -> Result<String, Response<Full<Bytes>>> {
    if request.version() != Version::HTTP_11 {
        return Err(bare(StatusCode::BAD_REQUEST, "HTTP/1.1 required"));
    }
    let upgrade = header_tokens(single_header(request.headers(), "upgrade"));
    let connection = header_tokens(single_header(request.headers(), "connection"));
    if !upgrade.iter().any(|token| token == "websocket")
        || !connection.iter().any(|token| token == "upgrade")
    {
        return Err(bare(StatusCode::BAD_REQUEST, "Upgrade request required"));
    }
    if single_header(request.headers(), "sec-websocket-version").map(str::trim) != Some("13") {
        return Err(bare_with_header(
            StatusCode::UPGRADE_REQUIRED,
            "Sec-WebSocket-Version: 13 required",
            "sec-websocket-version",
            "13",
        ));
    }
    let key = single_header(request.headers(), "sec-websocket-key")
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| bare(StatusCode::BAD_REQUEST, "Sec-WebSocket-Key required"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|_| bare(StatusCode::BAD_REQUEST, "Sec-WebSocket-Key is not base64"))?;
    if decoded.len() != 16 {
        return Err(bare(
            StatusCode::BAD_REQUEST,
            "Sec-WebSocket-Key must be 16 bytes",
        ));
    }
    Ok(derive_accept_key(key.as_bytes()))
}

/// The `/bridge` route, reached only by requests the pre-hyper probe
/// declined: plain HTTP errors for non-upgrade or failed handshakes. A
/// head the probe admits is never seen by this path.
pub(crate) fn respond(policy: &Policy, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let host = single_header(request.headers(), "host").map(str::to_owned);
    let origin = single_header(request.headers(), "origin").map(str::to_owned);
    // The listener's unconditional gate (WDA-S-02.3): wrong Host, foreign
    // Origin — refused before any handshake work. The WebSocket-specific
    // Origin requirement is WDA-WI-11's to add.
    if !policy.allows(host.as_deref(), origin.as_deref()) {
        return with_csp(policy.csp(), bare(StatusCode::FORBIDDEN, "Forbidden"));
    }
    if request.method() != Method::GET {
        return with_csp(
            policy.csp(),
            bare_with_header(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method not allowed",
                "allow",
                "GET",
            ),
        );
    }
    match accept_key(&request) {
        // Defense in depth only: the pre-hyper probe admits exactly these
        // heads, so a valid upgrade never reaches this path; if one ever
        // does, fail closed instead of upgrading over hyper.
        Ok(_) => with_csp(
            policy.csp(),
            bare(StatusCode::BAD_REQUEST, "Upgrade handshake failed"),
        ),
        Err(response) => with_csp(policy.csp(), response),
    }
}

// --- The pre-hyper upgrade -------------------------------------------------

/// What the peek validated as a fully-formed `GET /bridge` WebSocket
/// upgrade head — and what the manual handshake needs to serve it.
struct WsHead {
    /// Exact Host or `None`; the policy gate decides admission.
    host: Option<String>,
    /// Exact Origin, absent or foreign (both refused for WS upgrades).
    origin: Option<String>,
    /// `Sec-WebSocket-Accept` for the client nonce.
    accept: String,
}

/// Strictly parses a peeked head as a `GET /bridge` WebSocket upgrade.
/// Anything else — including a WS upgrade on another path or with any other
/// method/version/key — is not our shape and falls through to hyper, which
/// owns plain-HTTP serving and its error classes.
fn parse_bridge_ws_head(head: &[u8]) -> Option<WsHead> {
    let text = std::str::from_utf8(head).ok()?;
    let (request_line, rest) = text.split_once("\r\n")?;
    if request_line != "GET /bridge HTTP/1.1" {
        return None;
    }
    let mut host = None;
    let mut origin = None;
    let mut connection = None;
    let mut upgrade = None;
    let mut version = None;
    let mut key = None;
    for line in rest.split("\r\n") {
        // The head ends at the line break right after the last header.
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            // obs-fold or a malformed header; not our shape.
            return None;
        }
        let value = value.trim();
        let slot = match name.to_ascii_lowercase().as_str() {
            "host" => &mut host,
            "origin" => &mut origin,
            "connection" => &mut connection,
            "upgrade" => &mut upgrade,
            "sec-websocket-version" => &mut version,
            "sec-websocket-key" => &mut key,
            // Anything else is tolerated and irrelevant to the upgrade.
            _ => continue,
        };
        if slot.is_some() {
            // A duplicate of a required header is malformed for us.
            return None;
        }
        *slot = Some(value);
    }
    let connection_tokens = header_tokens(connection);
    let upgrade_tokens = header_tokens(upgrade);
    if !upgrade_tokens.iter().any(|token| token == "websocket")
        || !connection_tokens.iter().any(|token| token == "upgrade")
    {
        return None;
    }
    if version.map(str::trim) != Some("13") {
        return None;
    }
    // host is mandatory for HTTP/1.1 and for the policy gate to decide on.
    let host = host?;
    let key = key?.trim().to_string();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&key)
        .ok()?;
    if decoded.len() != 16 {
        return None;
    }
    Some(WsHead {
        host: Some(host.to_string()),
        origin: origin.map(str::to_string),
        accept: derive_accept_key(key.as_bytes()),
    })
}

/// The pre-hyper upgrade hook `loopback::serve_with` consumes: a strictly
/// gated, non-consuming head peek for the bridge WebSocket route.
pub(crate) struct BridgeUpgrade {
    policy: std::sync::Arc<Policy>,
    adapter: Option<std::sync::Arc<dyn InvocationAdapter>>,
    owners: GenerationArbiter,
}

impl Clone for BridgeUpgrade {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            adapter: self.adapter.clone(),
            owners: self.owners.clone(),
        }
    }
}

impl BridgeUpgrade {
    #[cfg(test)]
    pub(crate) fn new(policy: std::sync::Arc<Policy>) -> Self {
        Self {
            policy,
            adapter: None,
            owners: GenerationArbiter::default(),
        }
    }

    pub(crate) fn with_adapter(
        policy: std::sync::Arc<Policy>,
        adapter: std::sync::Arc<dyn InvocationAdapter>,
    ) -> Self {
        Self {
            policy,
            adapter: Some(adapter),
            owners: GenerationArbiter::default(),
        }
    }

    /// `true` exactly when the bounded head peek validates as a fully-formed
    /// `GET /bridge` WebSocket upgrade.
    pub(crate) fn is_websocket(&self, head: &[u8]) -> bool {
        parse_bridge_ws_head(head).is_some()
    }

    /// Takes over a connection the probe admitted: consumes exactly the
    /// peeked head, enforces the listener's Host/Origin gate before the
    /// handshake, writes a manual RFC 6455 `101`, and runs the session.
    /// `permit` is the connection's guard for the `CONNECTIONS` bound; it is
    /// held for the session's lifetime and dropped when it closes.
    pub(crate) async fn take_over(
        &self,
        mut socket: TcpStream,
        head: Vec<u8>,
        permit: OwnedSemaphorePermit,
        stop: CancellationToken,
    ) {
        // The caller consumed exactly the head from the socket; anything
        // after it (pipelined WS frames) stays in the kernel buffer.
        let Some(ws) = parse_bridge_ws_head(&head) else {
            // Probe mismatch (cannot happen): refuse rather than guess.
            return;
        };
        if ws.origin.is_none() || !self.policy.allows(ws.host.as_deref(), ws.origin.as_deref()) {
            let forbidden = format!(
                "HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\nx-content-type-options: nosniff\r\ncontent-security-policy: {}\r\ncontent-length: 9\r\nconnection: close\r\n\r\nForbidden",
                self.policy.csp(),
            );
            let _ = socket.write_all(forbidden.as_bytes()).await;
            return;
        }
        let csp = self.policy.csp();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\ncontent-security-policy: {csp}\r\nx-content-type-options: nosniff\r\n\r\n",
            accept = ws.accept,
        );
        let mut socket = socket;
        if socket.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        // S-02.4's first-auth deadline starts only after the 101 is fully
        // written; it is not reset by partial frames or later input.
        let auth_deadline = tokio::time::Instant::now() + AUTH_DEADLINE;
        let ws_stream =
            WebSocketStream::from_raw_socket(socket, Role::Server, Some(ws_config())).await;
        let owner = self.owners.new_connection();
        session(
            ws_stream,
            stop,
            permit,
            self.policy.clone(),
            auth_deadline,
            self.adapter.clone(),
            self.owners.clone(),
            owner,
        )
        .await;
        // The session returned; its permit dropped with it.
    }
}

// --- The session -----------------------------------------------------------

enum State {
    /// Nothing has been received; the first frame must be `auth`.
    WaitingForAuth,
    /// The auth frame was valid; further invokes are accepted.
    Authenticated,
    /// A `kind:"raw"` invoke is awaiting its binary body frame.
    AwaitingRaw(Invoke),
}

/// Write one adapter channel delivery on the connection's sole writer path.
/// JSON envelope precedes its optional raw-body frame, preserving the codec's
/// ordering and callback namespace encoding.
pub(crate) struct ChannelDelivery {
    pub(crate) id: u64,
    pub(crate) index: u64,
    pub(crate) message: Value,
    pub(crate) raw: Option<Vec<u8>>,
    pub(crate) generation: u64,
    pub(crate) owner_id: u64,
}

pub(crate) async fn write_channel_delivery(
    ws: &mut WebSocketStream<TcpStream>,
    id: u64,
    index: u64,
    message: &Value,
    raw: Option<&[u8]>,
) -> Result<(), String> {
    let envelope = match raw {
        Some(_) => encode_callback_raw(id, index),
        None => encode_callback_json(id, index, message),
    }
    .map_err(|error| error.0.to_string())?;
    ws.send(Message::text(envelope))
        .await
        .map_err(|error| error.to_string())?;
    if let Some(bytes) = raw {
        let frame = encode_binary_channel(id, bytes).map_err(|error| error.0.to_string())?;
        ws.send(Message::binary(frame))
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

async fn close_policy(ws: &mut WebSocketStream<TcpStream>, reason: &'static str) {
    close_with_reason(ws, CLOSE_POLICY, reason).await;
}

async fn close_with_reason(
    ws: &mut WebSocketStream<TcpStream>,
    code: CloseCode,
    reason: &'static str,
) {
    let close = ws.send(Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    })));
    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), close).await;
}

async fn close_authentication_failed(ws: &mut WebSocketStream<TcpStream>) {
    close_with_reason(ws, CLOSE_AUTHENTICATION_FAILED, "authentication failed").await;
}

async fn close_retired_owner(ws: &mut WebSocketStream<TcpStream>, owner: &ConnectionOwner) {
    match owner.close_kind() {
        1 => close_with_reason(ws, CloseCode::from(4001), "session superseded").await,
        2 => close_policy(ws, "delivery queue overloaded").await,
        _ => close_policy(ws, "bridge session retired").await,
    }
}

/// Registers `id` as in flight; refuses duplicates and a full backlog.
fn register(pending: &mut HashSet<u64>, id: u64) -> bool {
    if pending.len() >= MAX_PENDING_INVOKES || !pending.insert(id) {
        return false;
    }
    true
}

/// Runs one upgraded bridge connection until it closes. `permit` is the
/// connection's guard for the `CONNECTIONS` bound; it is held for the whole
/// session and dropped when this returns — never acquired twice, never
/// dropped early.
pub(crate) async fn session(
    socket: WebSocketStream<TcpStream>,
    stop: CancellationToken,
    _permit: OwnedSemaphorePermit,
    policy: std::sync::Arc<Policy>,
    auth_deadline: tokio::time::Instant,
    adapter: Option<std::sync::Arc<dyn InvocationAdapter>>,
    owners: GenerationArbiter,
    owner: Arc<ConnectionOwner>,
) {
    let mut ws = socket;
    let owner_cancel = owner.cancel();
    let mut state = State::WaitingForAuth;
    let mut pending: HashSet<u64> = HashSet::new();
    let (delivery_tx, mut delivery_rx) = tokio::sync::mpsc::channel::<ChannelDelivery>(32);
    let mut next_callback_id = CALLBACK_NAMESPACE_MIN;
    let mut used_callback_ids = HashSet::new();
    // The numeric auth-frame generation is opaque and connection-scoped.
    // Cross-connection ownership is handled separately by `GenerationArbiter`.
    let mut generation = 0u64;
    let mut token: Option<Zeroizing<String>> = None;
    let mut subscriptions = adapter
        .as_ref()
        .map(|adapter| adapter.create_subscriptions(delivery_tx.clone()));

    loop {
        enum Incoming {
            Socket(Option<Result<Message, tokio_tungstenite::tungstenite::Error>>),
            Delivery(Option<ChannelDelivery>),
        }
        let incoming = tokio::select! {
            message = ws.next() => Incoming::Socket(message),
            delivery = delivery_rx.recv() => Incoming::Delivery(delivery),
            () = owner_cancel.cancelled() => {
                close_retired_owner(&mut ws, &owner).await;
                break;
            }
            () = tokio::time::sleep_until(auth_deadline), if matches!(state, State::WaitingForAuth) => {
                close_with_reason(&mut ws, CLOSE_POLICY, "authentication timeout").await;
                break;
            }
            () = stop.cancelled() => {
                close_with_reason(&mut ws, CloseCode::Away, "daemon shutting down").await;
                break;
            }
        };
        let message = match incoming {
            Incoming::Delivery(Some(delivery)) => {
                if delivery.owner_id != owner.id() || !owners.is_current(&owner) {
                    continue;
                }
                if delivery.generation != generation {
                    continue;
                }
                if write_channel_delivery(
                    &mut ws,
                    delivery.id,
                    delivery.index,
                    &delivery.message,
                    delivery.raw.as_deref(),
                )
                .await
                .map_err(|error| {
                    eprintln!("bridge callback write failed; closing session: {error}");
                    error
                })
                .is_err()
                {
                    break;
                }
                continue;
            }
            Incoming::Delivery(None) => continue,
            Incoming::Socket(Some(Ok(message))) => message,
            Incoming::Socket(Some(Err(_))) | Incoming::Socket(None) => break,
        };
        match message {
            Message::Text(text) => {
                let frame = match parse_frame(text.as_str()) {
                    Ok(frame) => frame,
                    Err(_) => {
                        close_policy(&mut ws, "malformed frame").await;
                        break;
                    }
                };
                match std::mem::replace(&mut state, State::WaitingForAuth) {
                    State::WaitingForAuth => match frame {
                        Frame::Auth {
                            token: auth_token,
                            generation: auth_generation,
                        } => {
                            if !policy.token_matches(&auth_token) {
                                close_authentication_failed(&mut ws).await;
                                break;
                            }
                            // A failed or unauthenticated connection never
                            // acquires the active-owner slot.
                            owners.activate(&owner);
                            token = Some(Zeroizing::new(auth_token));
                            generation = auth_generation;
                            state = State::Authenticated;
                        }
                        Frame::Invoke(_) => {
                            close_policy(&mut ws, "auth must be the first frame").await;
                            break;
                        }
                    },
                    State::Authenticated => match frame {
                        Frame::Auth { .. } => {
                            close_policy(&mut ws, "connection is already authenticated").await;
                            break;
                        }
                        Frame::Invoke(invoke) => {
                            if !register(&mut pending, invoke.id) {
                                close_policy(&mut ws, "invoke id already pending or backlog full")
                                    .await;
                                break;
                            }
                            match invoke.body.clone() {
                                InvokeBody::Json(body) => {
                                    if let Some(adapter) = &adapter {
                                        let context = SessionContext {
                                            token: token
                                                .as_ref()
                                                .expect("auth precedes invoke")
                                                .clone(),
                                            generation,
                                        };
                                        while used_callback_ids.contains(&next_callback_id) {
                                            next_callback_id = next_callback_id.saturating_add(1);
                                        }
                                        let callback_id = next_callback_id;
                                        next_callback_id = next_callback_id.saturating_add(1);
                                        if callback_id > MAX_WIRE_ID {
                                            break;
                                        }
                                        let response = if invoke.cmd == "plugin:event|listen" {
                                            let event = body.get("event").and_then(Value::as_str);
                                            let target = body.get("target");
                                            let handler =
                                                body.get("handler").and_then(Value::as_u64);
                                            let exact_shape = body
                                                .as_object()
                                                .is_some_and(|object| object.len() == 3);
                                            match (
                                                exact_shape,
                                                event,
                                                target,
                                                handler,
                                                subscriptions.as_mut(),
                                            ) {
                                                (
                                                    true,
                                                    Some(event),
                                                    Some(target),
                                                    Some(handler),
                                                    Some(registry),
                                                ) if !used_callback_ids.contains(&handler) => {
                                                    let result = registry.listen(
                                                        event,
                                                        target,
                                                        handler,
                                                        generation,
                                                        owner.clone(),
                                                    );
                                                    if result.is_ok() {
                                                        used_callback_ids.insert(handler);
                                                    }
                                                    result.map(|event_id| {
                                                        AdapterResponse::Json(Value::Number(
                                                            event_id.into(),
                                                        ))
                                                    })
                                                }
                                                _ => Err(Value::String(
                                                    "invalid event listen arguments".into(),
                                                )),
                                            }
                                        } else if invoke.cmd == "plugin:event|unlisten" {
                                            let event = body.get("event").and_then(Value::as_str);
                                            let event_id =
                                                body.get("eventId").and_then(Value::as_u64);
                                            let exact_shape = body
                                                .as_object()
                                                .is_some_and(|object| object.len() == 2);
                                            match (
                                                exact_shape,
                                                event,
                                                event_id,
                                                subscriptions.as_mut(),
                                            ) {
                                                (
                                                    true,
                                                    Some(event),
                                                    Some(event_id),
                                                    Some(registry),
                                                ) => registry
                                                    .unlisten(event, event_id)
                                                    .map(|()| AdapterResponse::Json(Value::Null)),
                                                _ => Err(Value::String(
                                                    "invalid event unlisten arguments".into(),
                                                )),
                                            }
                                        } else {
                                            tokio::select! {
                                                result = adapter.invoke(
                                                    invoke.cmd,
                                                    CommandInput { body, raw_body: None, headers: invoke.headers },
                                                    context,
                                                    callback_id,
                                                    delivery_tx.clone(),
                                                    owner.clone(),
                                                ) => result,
                                                () = owner_cancel.cancelled() => {
                                                    close_retired_owner(&mut ws, &owner).await;
                                                    break;
                                                }
                                            }
                                        };
                                        if !owners.is_current(&owner) {
                                            close_retired_owner(&mut ws, &owner).await;
                                            break;
                                        }
                                        let outgoing = match response {
                                            Ok(AdapterResponse::Json(payload)) => {
                                                encode_invoke_ok(invoke.id, &payload)
                                                    .map(Message::text)
                                            }
                                            Ok(AdapterResponse::Raw(bytes)) => {
                                                encode_binary_response(invoke.id, &bytes)
                                                    .map(Message::binary)
                                            }
                                            Err(error) => encode_invoke_err(invoke.id, &error)
                                                .map(Message::text),
                                        };
                                        match outgoing {
                                            Ok(message) => {
                                                if ws.send(message).await.is_err() {
                                                    break;
                                                }
                                                pending.remove(&invoke.id);
                                                state = State::Authenticated;
                                            }
                                            Err(_) => break,
                                        }
                                    } else {
                                        state = State::Authenticated;
                                    }
                                }
                                InvokeBody::Raw => {
                                    state = State::AwaitingRaw(invoke);
                                }
                            }
                        }
                    },
                    State::AwaitingRaw(_) => {
                        // A text frame arrived where the raw body was due.
                        close_policy(&mut ws, "raw body frame expected").await;
                        break;
                    }
                }
            }
            Message::Binary(bytes) => match std::mem::replace(&mut state, State::WaitingForAuth) {
                State::AwaitingRaw(invoke) => {
                    if let Some(adapter) = &adapter {
                        let context = SessionContext {
                            token: token.as_ref().expect("auth precedes invoke").clone(),
                            generation,
                        };
                        while used_callback_ids.contains(&next_callback_id) {
                            next_callback_id = next_callback_id.saturating_add(1);
                        }
                        let callback_id = next_callback_id;
                        next_callback_id = next_callback_id.saturating_add(1);
                        if callback_id > MAX_WIRE_ID {
                            break;
                        }
                        let result = tokio::select! {
                            result = adapter.invoke(
                                invoke.cmd,
                                CommandInput {
                                    body: Value::Null,
                                    raw_body: Some(bytes.to_vec()),
                                    headers: invoke.headers,
                                },
                                context,
                                callback_id,
                                delivery_tx.clone(),
                                owner.clone(),
                            ) => result,
                            () = owner_cancel.cancelled() => {
                                close_retired_owner(&mut ws, &owner).await;
                                break;
                            }
                        };
                        if !owners.is_current(&owner) {
                            close_retired_owner(&mut ws, &owner).await;
                            break;
                        }
                        let outgoing = match result {
                            Ok(AdapterResponse::Json(payload)) => {
                                encode_invoke_ok(invoke.id, &payload).map(Message::text)
                            }
                            Ok(AdapterResponse::Raw(payload)) => {
                                encode_binary_response(invoke.id, &payload).map(Message::binary)
                            }
                            Err(error) => encode_invoke_err(invoke.id, &error).map(Message::text),
                        };
                        match outgoing {
                            Ok(message) => {
                                if ws.send(message).await.is_err() {
                                    break;
                                }
                                pending.remove(&invoke.id);
                                state = State::Authenticated;
                            }
                            Err(_) => break,
                        }
                    } else {
                        state = State::Authenticated;
                    }
                }
                _ => {
                    close_policy(&mut ws, "unexpected binary frame").await;
                    break;
                }
            },
            Message::Ping(payload) => {
                if ws.send(Message::Pong(payload)).await.is_err() {
                    break;
                }
            }
            Message::Pong(_) => {}
            Message::Close(_) => break,
            Message::Frame(_) => {}
        }
    }
    // `_permit` drops here: the upgraded socket releases its admission slot.
}

#[cfg(test)]
mod tests {
    //! WDA-S-03.1 (WDA-WI-08) acceptance surface: the codec is tested at the
    //! encode/decode boundary, and the endpoint at the real loopback
    //! WebSocket boundary through `loopback::bind`/`serve` and real
    //! tungstenite clients/raw sockets. Nothing here pins production seams:
    //! the listener, policy gate and upgrade path are the shipped ones.

    use super::*;
    use crate::loopback;
    use crate::web::Policy;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpStream;

    const RFC_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ=="; // "the sample nonce", 16 bytes (RFC 6455 example)
    const RFC_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn handler_names(source: &str, block_marker: &str) -> Vec<String> {
        let block = source
            .find(block_marker)
            .unwrap_or_else(|| panic!("missing handler block {block_marker:?}"));
        let macro_start = source[block..]
            .find("generate_handler![")
            .map(|offset| block + offset)
            .unwrap_or_else(|| panic!("missing generate_handler! in {block_marker:?}"));
        let open = source[macro_start..]
            .find('[')
            .map(|offset| macro_start + offset)
            .expect("handler macro has opening bracket");
        let mut depth = 0usize;
        let mut close = None;
        for (offset, character) in source[open..].char_indices() {
            match character {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.expect("handler macro has matching closing bracket");
        source[open + 1..close]
            .split(',')
            .filter_map(|item| {
                let path = item
                    .lines()
                    .map(str::trim)
                    .filter(|line| {
                        !line.is_empty() && !line.starts_with('#') && !line.starts_with("//")
                    })
                    .last()?;
                Some(path.rsplit("::").next().unwrap_or(path).trim().to_owned())
            })
            .collect()
    }

    fn adapter_command_names(source: &str) -> Vec<String> {
        let start = source
            .find("match command.as_str() {")
            .expect("adapter command match exists");
        let open = start + source[start..].find('{').expect("match has opening brace");
        let mut depth = 0usize;
        let mut close = None;
        for (offset, character) in source[open..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let block = &source[open + 1..close.expect("match has closing brace")];
        let mut names = Vec::new();
        for line in block.lines().filter(|line| line.contains("=>")) {
            let pattern = line.split("=>").next().unwrap_or_default();
            for (index, name) in pattern.split('"').enumerate() {
                if index % 2 == 1 && !name.is_empty() && !name.starts_with("plugin:event|") {
                    names.push(name.to_owned());
                }
            }
        }
        names
    }

    #[test]
    fn inventory_covers_the_registered_commands() {
        let application = handler_names(include_str!("lib.rs"), "fn commands<");
        let browser = handler_names(include_str!("lib.rs"), "let browser_commands");
        let mesh = handler_names(include_str!("mesh_compute.rs"), "pub(crate) fn commands()");
        let mut expected = std::collections::BTreeMap::<String, String>::new();
        for (group, names) in [
            ("application", application),
            ("browser", browser),
            ("mesh", mesh),
        ] {
            for name in names {
                assert!(
                    expected.insert(name.clone(), group.to_owned()).is_none(),
                    "duplicate registered command {name}"
                );
            }
        }

        let inventory: serde_json::Value =
            serde_json::from_str(include_str!("../command-inventory.json"))
                .expect("checked-in command inventory is valid JSON");
        assert_eq!(inventory["schema_version"], 1);
        let rows = inventory["rows"]
            .as_array()
            .expect("inventory rows are an array");
        let mut actual = std::collections::BTreeMap::<String, &serde_json::Value>::new();
        for row in rows {
            let name = row["name"].as_str().expect("row has a name").to_owned();
            assert!(
                actual.insert(name.clone(), row).is_none(),
                "inventory contains duplicate command {name}"
            );
            assert_eq!(
                row["group"].as_str(),
                expected.get(&name).map(String::as_str),
                "wrong or unregistered command group for {name}"
            );
            assert!(
                matches!(
                    row["argument_encoding"].as_str(),
                    Some("json" | "raw" | "both")
                ),
                "invalid argument encoding for {name}"
            );
            assert!(
                row["required_headers"]
                    .as_array()
                    .is_some_and(|headers| headers.iter().all(serde_json::Value::is_string)),
                "invalid required headers for {name}"
            );
            assert!(
                row["injected_context"]
                    .as_array()
                    .is_some_and(|context| context.iter().all(serde_json::Value::is_string)),
                "invalid injected context for {name}"
            );
            let permission = row["permission_class"].as_str().unwrap_or_default();
            assert!(
                matches!(permission, "open" | "bearer" | "window_only")
                    || permission.starts_with("plugin_grant:"),
                "invalid permission class for {name}"
            );
            assert!(
                matches!(
                    row["response_encoding"].as_str(),
                    Some("json" | "raw" | "both")
                ),
                "invalid response encoding for {name}"
            );
            assert!(
                row["channel_lifecycle"].as_str().is_some(),
                "missing channel lifecycle for {name}"
            );
            let headless = &row["headless"];
            assert!(
                headless["available"].as_bool().is_some(),
                "missing headless classification for {name}"
            );
            assert!(
                headless["degradation"].as_str().is_some(),
                "missing headless/degradation note for {name}"
            );
            if permission == "window_only" || headless["available"] == false {
                assert!(
                    headless["degradation"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("S-07."),
                    "window-dependent/degraded command lacks an S-07 note: {name}"
                );
            }
        }
        assert_eq!(
            actual.len(),
            expected.len(),
            "inventory row count differs from registered command count"
        );
        for name in expected.keys() {
            assert!(
                actual.contains_key(name),
                "registered command missing from inventory: {name}"
            );
        }

        let adapter = adapter_command_names(include_str!("bridge_adapter.rs"));
        let expected_adapter = [
            "app_agent_claim",
            "app_agent_create",
            "app_agent_git_auth",
            "app_agent_list",
            "app_agent_media",
            "app_agent_publish",
            "app_agent_publish_profile",
            "app_agent_query",
            "app_agent_remember",
            "app_agent_release",
            "app_agent_search_profiles",
            "app_agent_set_picture",
            "app_agent_upload",
            "app_agent_state_load",
            "app_agent_state_set",
            "identity_create",
            "identity_import",
            "identity_legacy_available",
            "plugin_catalog",
            "plugin_change",
            "plugin_managed_refresh",
            "identity_restore",
            "keep_awake_set",
            "pairing_status",
            "plugin_host_mcp_close",
            "plugin_host_mcp_reply",
            "plugin_host_mcp_serve",
            "plugin_host_process_bind_agent",
            "plugin_host_process_kill",
            "plugin_host_process_spawn",
            "plugin_host_process_tool_credential",
            "plugin_host_process_write",
            "plugin_host_read_file",
            "plugin_host_resolve_directory",
            "relay_agent_library",
            "relay_agent_memories_read",
            "relay_channel_sign",
            "legacy_communities",
            "relay_direct_message",
            "relay_http",
            "relay_sign",
            "relay_socket_close",
            "relay_socket_connect",
            "relay_socket_send",
            "relay_socket_start",
            "relay_upload_chunk",
            "relay_verify_signatures",
        ];
        assert_eq!(
            adapter.len(),
            expected_adapter.len(),
            "adapter dispatch set changed"
        );
        for name in expected_adapter {
            assert_eq!(
                adapter
                    .iter()
                    .filter(|found| found.as_str() == name)
                    .count(),
                1,
                "adapter command missing or duplicated: {name}"
            );
        }
        for name in adapter {
            assert!(
                expected_adapter.contains(&name.as_str()),
                "unexpected adapter-dispatched command: {name}"
            );
        }
    }

    // ---- helpers ---------------------------------------------------------

    fn auth_text(token: &str, generation: u64) -> Message {
        Message::text(
            serde_json::json!({ "type": "auth", "token": token, "generation": generation })
                .to_string(),
        )
    }

    fn invoke_text(id: u64, cmd: &str, body: Value) -> Message {
        Message::text(
            serde_json::json!({ "type": "invoke", "id": id, "cmd": cmd, "body": body }).to_string(),
        )
    }

    fn invoke_text_with_headers(id: u64, cmd: &str, headers: Value) -> Message {
        Message::text(
            serde_json::json!({
                "type": "invoke",
                "id": id,
                "cmd": cmd,
                "body": {"kind":"raw"},
                "headers": headers
            })
            .to_string(),
        )
    }

    /// Builds the same answer closure shape `web::start` uses: `/bridge` to
    /// the bridge, everything else to a trivial marker response so the
    /// "same listener" property is assertable in one test.
    fn test_answer(
        policy: Arc<Policy>,
    ) -> impl Fn(
        Request<Incoming>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Response<Full<Bytes>>, std::convert::Infallible>,
                > + Send,
        >,
    > + Clone
           + Send
           + Sync
           + 'static {
        move |request: Request<Incoming>| {
            let policy = policy.clone();
            Box::pin(async move {
                if request.uri().path() == "/bridge" {
                    return Ok(crate::bridge::respond(policy.as_ref(), request));
                }
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Full::new(Bytes::from("fallback")))
                    .expect("fallback response"))
            })
        }
    }

    /// Cancels the fixture listener's stop token when the test ends —
    /// including on panic — so each fixture's listener and any upgraded
    /// sessions it admitted always retire instead of leaking sockets and
    /// permits into the process.
    struct StopGuard(Option<CancellationToken>);

    impl Drop for StopGuard {
        fn drop(&mut self) {
            if let Some(stop) = self.0.take() {
                stop.cancel();
            }
        }
    }

    impl StopGuard {
        fn cancel(&self) {
            if let Some(stop) = &self.0 {
                stop.cancel();
            }
        }
    }

    /// Binds a loopback listener wired like production: the pre-hyper probe
    /// owns the upgrades; the answer owns everything else.
    async fn bridge_port() -> (u16, StopGuard) {
        bridge_port_with_adapter(None).await
    }

    async fn bridge_port_with_adapter(
        adapter: Option<std::sync::Arc<dyn InvocationAdapter>>,
    ) -> (u16, StopGuard) {
        let (listener, authority) = loopback::bind().expect("bind loopback");
        let port: u16 = authority
            .strip_prefix("127.0.0.1:")
            .and_then(|port| port.parse().ok())
            .expect("loopback authority");
        let policy = Arc::new(Policy::for_port(
            port,
            Zeroizing::new("test-token".to_string()),
        ));
        let answer = test_answer(policy.clone());
        let upgrade = match adapter {
            Some(adapter) => BridgeUpgrade::with_adapter(policy, adapter),
            None => BridgeUpgrade::new(policy),
        };
        let stop = CancellationToken::new();
        tauri::async_runtime::spawn(loopback::serve_with(
            listener,
            stop.clone(),
            answer,
            Some(std::sync::Arc::new(upgrade)),
        ));
        (port, StopGuard(Some(stop)))
    }

    /// Reads response head bytes up to `\r\n\r\n`, bounded by `budget`.
    async fn read_head(stream: &mut TcpStream, budget: Duration) -> Option<String> {
        let read = async {
            let mut head = Vec::new();
            let mut buffer = [0u8; 2048];
            loop {
                let count = stream.read(&mut buffer).await.ok()?;
                if count == 0 {
                    return Some(String::from_utf8_lossy(&head).into_owned());
                }
                head.extend_from_slice(&buffer[..count]);
                if head.windows(4).any(|window| window == b"\r\n\r\n") {
                    return Some(String::from_utf8_lossy(&head).into_owned());
                }
            }
        };
        tokio::time::timeout(budget, read).await.ok().flatten()
    }

    /// Writes a raw RFC 6455 upgrade request and returns the stream plus
    /// the response head.
    async fn raw_upgrade_raw(port: u16, host: &str, origin: Option<&str>) -> (TcpStream, String) {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        let mut request = format!(
            "GET /bridge HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_KEY}\r\nSec-WebSocket-Version: 13\r\n"
        );
        if let Some(origin) = origin {
            request.push_str(&format!("Origin: {origin}\r\n"));
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write head");
        let head = read_head(&mut stream, Duration::from_secs(2))
            .await
            .expect("response head within budget");
        (stream, head)
    }

    async fn raw_upgrade(port: u16, host: &str, origin: Option<&str>) -> (TcpStream, String) {
        let expected = format!("http://localhost:{port}");
        raw_upgrade_raw(port, host, Some(origin.unwrap_or(&expected))).await
    }

    async fn ws_client(
        port: u16,
        origin: Option<&str>,
    ) -> WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let url = format!("ws://localhost:{port}/bridge");
        let mut request = url.into_client_request().expect("client request");
        // tungstenite fills Host and the Sec-WebSocket headers; the upgrade
        // headers are the caller's (matching what a browser sends).
        request
            .headers_mut()
            .insert("connection", "Upgrade".parse().expect("connection header"));
        request
            .headers_mut()
            .insert("upgrade", "websocket".parse().expect("upgrade header"));
        let expected_origin = format!("http://localhost:{port}");
        request.headers_mut().insert(
            "origin",
            origin
                .unwrap_or(&expected_origin)
                .parse()
                .expect("origin header"),
        );
        let (ws, response) = tokio::time::timeout(
            Duration::from_secs(2),
            tokio_tungstenite::connect_async(request),
        )
        .await
        .expect("upgrade within budget")
        .expect("upgrade");
        assert_eq!(response.status().as_u16(), 101);
        ws
    }

    /// Asserts the next frame is a server close with the given code.
    async fn expect_close_code(
        ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
        code: CloseCode,
        context: &str,
    ) {
        let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap_or_else(|_| panic!("{context}: timed out waiting for the close frame"))
            .expect("stream ended before a frame arrived")
            .expect("frame failed to decode");
        match message {
            Message::Close(Some(frame)) => assert_eq!(frame.code, code, "{context}"),
            other => panic!("{context}: expected a close frame, got {other:?}"),
        }
    }

    /// Asserts the server emits nothing for a bounded window; the expected
    /// state of a well-formed invoke with no adapter yet.
    async fn expect_silence<S>(ws: &mut S, context: &str)
    where
        S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
            + Unpin,
    {
        let silence = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
        assert!(
            silence.is_err(),
            "{context}: server unexpectedly emitted a frame or closed"
        );
    }

    fn status_code(head: &str) -> u16 {
        head.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("status code in response head")
    }

    // ---- codec: parsing and validation -----------------------------------

    #[test]
    fn auth_frame_parses_and_preserves_values() {
        let frame = parse_frame(r#"{"type":"auth","token":"daemon-token","generation":7}"#)
            .expect("valid auth frame");
        assert_eq!(
            frame,
            Frame::Auth {
                token: "daemon-token".to_string(),
                generation: 7,
            }
        );
    }

    #[test]
    fn auth_frame_rejects_bad_shapes_and_ranges() {
        for (text, case) in [
            (r#"{"type":"auth","token":"t"}"#, "missing generation"),
            (
                r#"{"type":"auth","token":"t","generation":1,"extra":true}"#,
                "extra member",
            ),
            (
                r#"{"type":"auth","token":1,"generation":1}"#,
                "token not a string",
            ),
            (r#"{"type":"auth","generation":1}"#, "missing token"),
            (
                r#"{"type":"auth","token":"t","generation":"1"}"#,
                "generation as string",
            ),
            (
                r#"{"type":"auth","token":"t","generation":-1}"#,
                "negative generation",
            ),
            (
                r#"{"type":"auth","token":"t","generation":1.5}"#,
                "fractional generation",
            ),
            // 2^53 is beyond the browser-safe range and is rejected.
            (
                r#"{"type":"auth","token":"t","generation":9007199254740992}"#,
                "2^53 generation",
            ),
            (
                r#"{"type":"auth","token":"t","generation":18446744073709551615}"#,
                "u64::MAX generation",
            ),
        ] {
            assert!(parse_frame(text).is_err(), "{case}");
        }
        // 2^53-1 is the largest browser-safe generation and is accepted.
        let frame = parse_frame(r#"{"type":"auth","token":"t","generation":9007199254740991}"#)
            .expect("2^53-1 generation is valid");
        assert_eq!(
            frame,
            Frame::Auth {
                token: "t".to_string(),
                generation: MAX_WIRE_ID,
            }
        );
    }

    #[test]
    fn invoke_json_frame_parses_with_headers_preserved() {
        let frame = parse_frame(
            r#"{"type":"invoke","id":3,"cmd":"relay_publish","body":{"kind":"json","value":{"note":"hi","nested":[1,true,null]}},"headers":{"content-type":"application/json","x-attempt":"2"}}"#,
        )
        .expect("valid invoke");
        let Frame::Invoke(invoke) = frame else {
            panic!("expected an invoke frame");
        };
        assert_eq!(invoke.id, 3);
        assert_eq!(invoke.cmd, "relay_publish");
        assert_eq!(
            invoke.body,
            InvokeBody::Json(serde_json::json!({"note":"hi","nested":[1,true,null]}))
        );
        let headers = invoke.headers.expect("headers preserved");
        assert_eq!(
            headers["content-type"],
            Value::String("application/json".to_string())
        );
        assert_eq!(headers["x-attempt"], Value::String("2".to_string()));

        // A JSON body of null is a legal payload; null is reserved only as
        // the *channel raw-ref* marker, never as a payload discriminant.
        let frame = parse_frame(
            r#"{"type":"invoke","id":4,"cmd":"c","body":{"kind":"json","value":null}}"#,
        )
        .expect("null json value is a valid payload");
        assert_eq!(
            frame,
            Frame::Invoke(Invoke {
                id: 4,
                cmd: "c".to_string(),
                body: InvokeBody::Json(Value::Null),
                headers: None,
            })
        );
    }

    #[test]
    fn invoke_raw_body_frame_parses() {
        let frame = parse_frame(
            r#"{"type":"invoke","id":9,"cmd":"relay_upload_chunk","body":{"kind":"raw"},"headers":{"content-type":"application/octet-stream"}}"#,
        )
        .expect("valid raw invoke");
        let Frame::Invoke(invoke) = frame else {
            panic!("expected an invoke frame");
        };
        assert_eq!(invoke.body, InvokeBody::Raw);
        assert_eq!(
            invoke.headers.expect("headers preserved")["content-type"],
            Value::String("application/octet-stream".to_string())
        );
        for (text, case) in [
            (
                r#"{"type":"invoke","id":5,"cmd":"c","body":{"kind":"raw","value":[]}}"#,
                "raw body carrying a value",
            ),
            (
                r#"{"type":"invoke","id":5,"cmd":"c","body":{"kind":"raw","extra":1}}"#,
                "raw body with extra member",
            ),
            (
                r#"{"type":"invoke","id":5,"cmd":"c","body":{"kind":"yaml"}}"#,
                "unknown body kind",
            ),
            (
                r#"{"type":"invoke","id":5,"cmd":"c","body":{}}"#,
                "missing body kind",
            ),
            (
                r#"{"type":"invoke","id":5,"cmd":"c","body":"raw"}"#,
                "body not an object",
            ),
        ] {
            assert!(parse_frame(text).is_err(), "{case}");
        }
    }

    #[test]
    fn invoke_id_namespace_and_53bit_rules() {
        let at = |id: u64| {
            parse_frame(&format!(
                r#"{{"type":"invoke","id":{id},"cmd":"c","body":{{"kind":"json","value":null}}}}"#
            ))
        };
        assert!(at(0).is_ok());
        assert!(
            at(INVOKE_NAMESPACE_MAX).is_ok(),
            "2^52-1 is the top invoke id"
        );
        assert!(
            at(INVOKE_NAMESPACE_MAX + 1).is_err(),
            "2^52 enters the callback namespace"
        );
        assert!(at(MAX_WIRE_ID).is_err());
        for (text, case) in [
            (
                r#"{"type":"invoke","id":9007199254740992,"cmd":"c","body":{"kind":"json","value":null}}"#,
                "2^53 is not browser-safe",
            ),
            (
                r#"{"type":"invoke","id":-1,"cmd":"c","body":{"kind":"json","value":null}}"#,
                "negative id",
            ),
            (
                r#"{"type":"invoke","id":1.5,"cmd":"c","body":{"kind":"json","value":null}}"#,
                "fractional id",
            ),
            (
                r#"{"type":"invoke","id":"1","cmd":"c","body":{"kind":"json","value":null}}"#,
                "id as string",
            ),
            (
                r#"{"type":"invoke","cmd":"c","body":{"kind":"json","value":null}}"#,
                "missing id",
            ),
        ] {
            assert!(parse_frame(text).is_err(), "{case}");
        }
    }

    #[test]
    fn invoke_rejects_bad_frames() {
        for (text, case) in [
            (
                r#"{"type":"invoke","id":1,"cmd":"c","body":{"kind":"json","value":null},"extra":1}"#,
                "extra invoke member",
            ),
            (
                r#"{"type":"invoke","id":1,"cmd":"","body":{"kind":"json","value":null}}"#,
                "empty cmd",
            ),
            (
                r#"{"type":"invoke","id":1,"cmd":7,"body":{"kind":"json","value":null}}"#,
                "cmd not a string",
            ),
            (
                r#"{"type":"invoke","id":1,"cmd":"c","body":{"kind":"json","value":null},"headers":[]}"#,
                "headers not an object",
            ),
            (
                r#"{"type":"invoke","id":1,"cmd":"c","body":{"kind":"json","value":null},"headers":{"x":1}}"#,
                "header value not a string",
            ),
            (r#"{"type":"bogus","id":1}"#, "unknown frame type"),
            (r#"{"id":1}"#, "missing type"),
            (r#"not json"#, "malformed JSON"),
        ] {
            assert!(parse_frame(text).is_err(), "{case}");
        }
    }

    // ---- codec: server-frame encoding round trips -------------------------

    #[test]
    fn server_json_frames_round_trip() {
        let ok = encode_invoke_ok(7, &serde_json::json!({"pong": true})).expect("encode");
        let parsed: Value = serde_json::from_str(&ok).expect("invoke_ok decodes");
        assert_eq!(
            parsed,
            serde_json::json!({"type": "invoke_ok", "id": 7, "payload": {"pong": true}})
        );
        let err = encode_invoke_err(7, &serde_json::json!({"code": "denied"})).expect("encode");
        let parsed: Value = serde_json::from_str(&err).expect("invoke_err decodes");
        assert_eq!(
            parsed,
            serde_json::json!({"type": "invoke_err", "id": 7, "error": {"code": "denied"}})
        );
    }

    #[test]
    fn callback_envelope_shapes_are_exact() {
        let callback_id = CALLBACK_NAMESPACE_MIN + 5;
        let json = encode_callback_json(callback_id, 0, &serde_json::json!("chunk"))
            .expect("json delivery");
        let parsed: Value = serde_json::from_str(&json).expect("decodes");
        assert_eq!(
            parsed,
            serde_json::json!({"type": "callback", "id": callback_id, "envelope": {"index": 0, "message": "chunk"}})
        );

        // The raw-ref marker: message is null and the payload follows as a
        // 0x02 binary frame carrying the callback id.
        let raw = encode_callback_raw(callback_id, 1).expect("raw-ref delivery");
        let parsed: Value = serde_json::from_str(&raw).expect("decodes");
        assert_eq!(
            parsed,
            serde_json::json!({"type": "callback", "id": callback_id, "envelope": {"index": 1, "message": null}})
        );

        // The termination envelope carries no `message` at all.
        let end = encode_callback_end(callback_id, 2).expect("end envelope");
        let parsed: Value = serde_json::from_str(&end).expect("decodes");
        assert_eq!(
            parsed,
            serde_json::json!({"type": "callback", "id": callback_id, "envelope": {"index": 2, "end": true}})
        );
        assert!(parsed["envelope"].get("message").is_none());

        // null is rejected as an ordinary JSON delivery message.
        assert!(encode_callback_json(callback_id, 3, &Value::Null).is_err());
        // Callback IDs must live in the callback namespace; 0 is rejected.
        assert!(encode_callback_json(0, 0, &serde_json::json!("x")).is_err());
        assert!(encode_callback_raw(INVOKE_NAMESPACE_MAX, 0).is_err());
        assert!(encode_callback_end(MAX_WIRE_ID + 1, 0).is_err());
        assert!(encode_callback_end(callback_id, MAX_WIRE_ID + 1).is_err());
    }

    #[test]
    fn binary_response_and_channel_frames_round_trip() {
        let response = encode_binary_response(42, b"payload").expect("encode");
        assert_eq!(response[0], 0x01);
        assert_eq!(&response[1..9], &42u64.to_le_bytes());
        assert_eq!(&response[9..], b"payload");
        assert_eq!(
            decode_binary_frame(&response).expect("decode"),
            BinaryFrame::Response {
                id: 42,
                bytes: b"payload"
            }
        );

        let callback_id = CALLBACK_NAMESPACE_MIN + 1;
        let channel = encode_binary_channel(callback_id, b"\x00\xff\x10").expect("encode");
        assert_eq!(channel[0], 0x02);
        assert_eq!(&channel[1..9], &callback_id.to_le_bytes());
        assert_eq!(&channel[9..], b"\x00\xff\x10");
        assert_eq!(
            decode_binary_frame(&channel).expect("decode"),
            BinaryFrame::Channel {
                id: callback_id,
                bytes: b"\x00\xff\x10"
            }
        );

        // Cross-namespace tags and IDs are rejected.
        assert!(encode_binary_response(CALLBACK_NAMESPACE_MIN, b"x").is_err());
        assert!(encode_binary_channel(INVOKE_NAMESPACE_MAX, b"x").is_err());
        assert!(decode_binary_frame(&[0x03, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_binary_frame(&[0x01, 1, 2, 3]).is_err());
        // A 0x01 frame whose ID is in the callback namespace is rejected.
        let mut wrong = vec![0x01];
        wrong.extend_from_slice(&CALLBACK_NAMESPACE_MIN.to_le_bytes());
        wrong.extend_from_slice(b"x");
        assert!(decode_binary_frame(&wrong).is_err());
    }

    // ---- endpoint: the real loopback WebSocket boundary -------------------

    #[tokio::test]
    async fn the_upgrade_handshake_carries_sec_websocket_accept() {
        let (port, _stop) = bridge_port().await;
        let (stream, head) = raw_upgrade(port, &format!("localhost:{port}"), None).await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        let accept = head
            .lines()
            .find(|line| {
                line.len() > 21 && line[..21].eq_ignore_ascii_case("sec-websocket-accept:")
            })
            .map(|line| line[21..].trim().to_string())
            .expect("Sec-WebSocket-Accept header");
        assert_eq!(
            accept, RFC_ACCEPT,
            "accept is the RFC 6455 derivation for the RFC nonce"
        );
        // The served policy rides the 101 too; it is applied uniformly.
        assert!(
            head.to_ascii_lowercase()
                .contains("content-security-policy"),
            "{head}"
        );
        drop(stream);
    }

    #[tokio::test]
    async fn the_upgrade_requires_the_exact_host_and_origin() {
        let (port, _stop) = bridge_port().await;
        let exact_host = format!("localhost:{port}");
        let (_, head) = raw_upgrade(port, &format!("127.0.0.1:{port}"), None).await;
        assert_eq!(status_code(&head), 403, "IP Host alias is refused");
        let (_, head) = raw_upgrade(port, "localhost", None).await;
        assert_eq!(status_code(&head), 403, "portless Host is refused");
        let (_, head) = raw_upgrade(port, &exact_host, Some("http://evil.example")).await;
        assert_eq!(status_code(&head), 403, "foreign Origin is refused");
        // CSP on the rejection too (the listener applies it uniformly),
        // and no upgrade accept leaked.
        assert!(
            head.to_ascii_lowercase()
                .contains("content-security-policy"),
            "{head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("sec-websocket-accept"),
            "{head}"
        );
        // The canonical Origin is admitted; unlike pages/assets, a WS
        // upgrade without Origin is rejected before the 101.
        let (_, head) =
            raw_upgrade(port, &exact_host, Some(&format!("http://localhost:{port}"))).await;
        assert_eq!(status_code(&head), 101);
        let (_, head) = raw_upgrade_raw(port, &exact_host, None).await;
        assert_eq!(status_code(&head), 403, "missing Origin is refused");
        let head = raw_request(
            port,
            &format!("GET /bridge HTTP/1.1\r\nHost: {exact_host}\r\nOrigin: http://localhost:{port}\r\nOrigin: http://localhost:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"),
        )
        .await;
        assert_eq!(status_code(&head), 403, "duplicate Origin is refused");
    }

    /// Writes an arbitrary raw request and reads the response head.
    async fn raw_request(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write head");
        read_head(&mut stream, Duration::from_secs(2))
            .await
            .expect("response head within budget")
    }

    #[tokio::test]
    async fn malformed_upgrade_handshakes_are_http_errors() {
        let (port, _stop) = bridge_port().await;
        let exact_host = format!("localhost:{port}");
        // Missing Sec-WebSocket-Key.
        let head = raw_request(
            port,
            &format!("GET /bridge HTTP/1.1\r\nHost: {exact_host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"),
        )
        .await;
        assert_eq!(status_code(&head), 400);
        // Sec-WebSocket-Version 12: refused with the required version advertised.
        let head = raw_request(
            port,
            &format!("GET /bridge HTTP/1.1\r\nHost: {exact_host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_KEY}\r\nSec-WebSocket-Version: 12\r\n\r\n"),
        )
        .await;
        assert_eq!(status_code(&head), 426);
        assert!(
            head.to_ascii_lowercase()
                .contains("sec-websocket-version: 13"),
            "{head}"
        );
        // No upgrade headers at all: not an upgrade.
        let head = raw_request(
            port,
            &format!("GET /bridge HTTP/1.1\r\nHost: {exact_host}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status_code(&head), 400);
        // Wrong method: the route admits GET only.
        let head = raw_request(
            port,
            &format!("POST /bridge HTTP/1.1\r\nHost: {exact_host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status_code(&head), 405);
    }

    #[tokio::test]
    async fn bridge_shares_the_loopback_listener_with_the_http_routes() {
        let (port, _stop) = bridge_port().await;
        let (_, head) = raw_upgrade(port, &format!("localhost:{port}"), None).await;
        assert_eq!(status_code(&head), 101);
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write");
        let head = read_head(&mut stream, Duration::from_secs(2))
            .await
            .expect("head");
        assert_eq!(
            status_code(&head),
            404,
            "the same listener serves the fallback HTTP route"
        );
    }

    #[tokio::test]
    async fn auth_must_be_the_first_frame() {
        let (port, _stop) = bridge_port().await;
        // A well-formed invoke before auth closes the connection.
        let mut ws = ws_client(port, None).await;
        ws.send(invoke_text(
            1,
            "relay_publish",
            serde_json::json!({"kind": "json", "value": null}),
        ))
        .await
        .expect("send invoke");
        expect_close_code(&mut ws, CloseCode::Policy, "invoke before auth").await;

        // A malformed JSON first frame closes the connection.
        let mut ws = ws_client(port, None).await;
        ws.send(Message::text("this is not json"))
            .await
            .expect("send garbage");
        expect_close_code(&mut ws, CloseCode::Policy, "malformed JSON first frame").await;

        // An unknown frame type closes the connection.
        let mut ws = ws_client(port, None).await;
        ws.send(Message::text(r#"{"type":"attach","id":1}"#))
            .await
            .expect("send unknown type");
        expect_close_code(&mut ws, CloseCode::Policy, "unknown first frame type").await;

        // An auth frame out of range closes the connection.
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("token", MAX_WIRE_ID + 1))
            .await
            .expect("send out-of-range generation");
        expect_close_code(&mut ws, CloseCode::Policy, "generation beyond 53 bits").await;

        // A binary frame before auth closes the connection.
        let mut ws = ws_client(port, None).await;
        ws.send(Message::binary(vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0]))
            .await
            .expect("send binary");
        expect_close_code(&mut ws, CloseCode::Policy, "binary frame before auth").await;
    }

    #[tokio::test]
    async fn the_auth_frame_order_is_enforced_after_authentication_too() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        // Authentication is accepted but the connection is not dispatched;
        // a second auth frame is not part of the vocabulary.
        ws.send(auth_text("test-token", 2))
            .await
            .expect("send second auth");
        expect_close_code(&mut ws, CloseCode::Policy, "second auth frame").await;
    }

    #[tokio::test]
    async fn an_arbitrary_token_is_rejected_by_wda_wi_11() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("definitely-not-the-daemon-token", 1))
            .await
            .expect("send auth");
        expect_close_code(&mut ws, CLOSE_AUTHENTICATION_FAILED, "invalid bearer token").await;
    }

    #[tokio::test]
    async fn missing_token_auth_frame_is_rejected_before_dispatch() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(Message::text(r#"{"type":"auth","generation":1}"#))
            .await
            .expect("send malformed auth");
        expect_close_code(&mut ws, CLOSE_POLICY, "malformed auth frame").await;
    }

    #[tokio::test]
    async fn a_late_auth_frame_cannot_revive_a_failed_connection() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("invalid", 1))
            .await
            .expect("send invalid auth");
        expect_close_code(&mut ws, CLOSE_AUTHENTICATION_FAILED, "invalid bearer token").await;
        let result = ws.send(auth_text("test-token", 2)).await;
        assert!(result.is_err(), "the failed connection is already closed");
    }

    #[tokio::test]
    async fn failed_authentication_does_not_retire_the_current_owner() {
        let publisher = crate::bridge_adapter::EventPublisher::default();
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("headless mock app");
        let fi = crate::federated_identity::FederatedIdentity::unconfigured();
        fi.watch(app.handle().clone(), publisher.clone());
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::with_publisher(
            app.handle().clone(),
            publisher,
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let callback = CALLBACK_NAMESPACE_MIN + 701;
        let mut current = ws_client(port, None).await;
        current
            .send(auth_text("test-token", 99))
            .await
            .expect("authenticate current owner");
        current
            .send(invoke_text(
                1,
                "plugin:event|listen",
                serde_json::json!({"kind":"json","value":{"event":"federated-identity","target":{"kind":"Any"},"handler":callback}}),
            ))
            .await
            .expect("subscribe current owner");
        let listen = tokio::time::timeout(Duration::from_secs(2), current.next())
            .await
            .expect("listen response deadline")
            .expect("listen response")
            .expect("listen frame");
        assert!(matches!(listen, Message::Text(_)));

        let mut rejected = ws_client(port, None).await;
        rejected
            .send(auth_text("not-the-daemon-token", 1))
            .await
            .expect("send invalid auth from second connection");
        expect_close_code(
            &mut rejected,
            CLOSE_AUTHENTICATION_FAILED,
            "invalid second connection auth",
        )
        .await;

        // A real FI producer event still reaches the original active owner;
        // an unauthenticated contender must not retire its delivery slot.
        fi.note_clock_offset(Some(9));
        let delivery = tokio::time::timeout(Duration::from_secs(2), current.next())
            .await
            .expect("current-owner delivery deadline")
            .expect("current-owner delivery")
            .expect("current-owner delivery frame");
        let Message::Text(delivery) = delivery else {
            panic!("expected owner callback delivery, got {delivery:?}")
        };
        let delivery: Value = serde_json::from_str(delivery.as_str()).expect("callback JSON");
        assert_eq!(delivery["id"], callback);
        assert_eq!(delivery["envelope"]["message"]["payload"]["clockOffset"], 9);
    }

    #[tokio::test]
    async fn first_auth_deadline_closes_an_idle_upgraded_connection() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        let result = tokio::time::timeout(AUTH_DEADLINE + Duration::from_secs(2), async {
            loop {
                match ws.next().await {
                    Some(Ok(Message::Close(Some(frame)))) => {
                        assert_eq!(frame.code, CLOSE_POLICY);
                        assert_eq!(frame.reason, "authentication timeout");
                        break;
                    }
                    Some(Ok(_)) => continue,
                    other => panic!("expected auth deadline close, got {other:?}"),
                }
            }
        })
        .await;
        assert!(result.is_ok(), "auth deadline must be timeout-bounded");
    }

    #[tokio::test]
    async fn json_invoke_sequence_is_accepted_and_remains_pending() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        ws.send(invoke_text(
            11,
            "relay_publish",
            serde_json::json!({"kind": "json", "value": {"body": "hi"}}),
        ))
        .await
        .expect("send invoke");
        // The headers form of the invoke is equally accepted.
        let with_headers = serde_json::json!({
            "type": "invoke",
            "id": 12,
            "cmd": "relay_upload_chunk",
            "body": {"kind": "json", "value": null},
            "headers": {"content-type": "application/octet-stream", "x-chunk": "0"}
        });
        ws.send(Message::text(with_headers.to_string()))
            .await
            .expect("send invoke with headers");
        // This codec-only fixture uses no adapter; production wires the
        // adapter into the accepted session.
        expect_silence(&mut ws, "well-formed invokes").await;

        // A well-formed invoke ID cannot be reused while pending.
        ws.send(invoke_text(
            11,
            "relay_publish",
            serde_json::json!({"kind": "json", "value": null}),
        ))
        .await
        .expect("send duplicate id");
        expect_close_code(&mut ws, CloseCode::Policy, "invoke id reused while pending").await;
    }

    #[tokio::test]
    async fn raw_invoke_sequence_parses_and_remains_pending() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        let invoke = serde_json::json!({
            "type": "invoke",
            "id": 21,
            "cmd": "relay_upload_chunk",
            "body": {"kind": "raw"},
            "headers": {"content-type": "application/octet-stream"}
        });
        ws.send(Message::text(invoke.to_string()))
            .await
            .expect("send raw invoke");
        // The one binary frame carrying the raw request bytes completes the body.
        ws.send(Message::binary(vec![0xde, 0xad, 0xbe, 0xef]))
            .await
            .expect("send raw body");
        expect_silence(&mut ws, "raw invoke with body").await;

        // After exactly one raw body, a further binary frame is unexpected.
        ws.send(Message::binary(vec![0x01]))
            .await
            .expect("send extra binary");
        expect_close_code(&mut ws, CloseCode::Policy, "extra binary frame after body").await;
    }

    #[tokio::test]
    async fn missing_raw_body_fails_the_connection() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        ws.send(invoke_text(
            31,
            "relay_upload_chunk",
            serde_json::json!({"kind": "raw"}),
        ))
        .await
        .expect("send raw invoke");
        // A text frame where the raw binary was due fails the connection.
        ws.send(invoke_text(
            32,
            "relay_publish",
            serde_json::json!({"kind": "json", "value": null}),
        ))
        .await
        .expect("send text frame instead of body");
        expect_close_code(&mut ws, CloseCode::Policy, "raw body missing").await;
    }

    #[tokio::test]
    async fn a_binary_frame_without_a_pending_raw_fails_the_connection() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        // An invoke with an inline JSON body leaves no raw body pending.
        ws.send(invoke_text(
            41,
            "relay_publish",
            serde_json::json!({"kind": "json", "value": null}),
        ))
        .await
        .expect("send json invoke");
        ws.send(Message::binary(vec![0xde, 0xad]))
            .await
            .expect("send unexpected binary");
        expect_close_code(
            &mut ws,
            CloseCode::Policy,
            "binary frame without pending raw body",
        )
        .await;
    }

    #[tokio::test]
    async fn invoke_ids_outside_the_invoke_namespace_close_the_connection() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        // 2^52 is the first callback-namespace ID; the bridge rejects it for invokes.
        ws.send(Message::text(format!(
            r#"{{"type":"invoke","id":{},"cmd":"c","body":{{"kind":"json","value":null}}}}"#,
            CALLBACK_NAMESPACE_MIN
        )))
        .await
        .expect("send callback-namespace id");
        expect_close_code(
            &mut ws,
            CloseCode::Policy,
            "invoke id in the callback namespace",
        )
        .await;
    }

    #[tokio::test]
    async fn ping_is_answered_and_malformed_frames_close() {
        let (port, _stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        ws.send(Message::Ping(Bytes::from_static(b"keepalive")))
            .await
            .expect("send ping");
        let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("pong within budget")
            .expect("frame")
            .expect("frame decodes");
        match message {
            Message::Pong(payload) => assert_eq!(&payload[..], b"keepalive"),
            other => panic!("expected pong, got {other:?}"),
        }
        ws.send(Message::text(r#"{"type":"bogus","id":1}"#))
            .await
            .expect("send unknown type");
        expect_close_code(&mut ws, CloseCode::Policy, "unknown frame type after auth").await;
    }

    #[tokio::test]
    async fn upgraded_connections_hold_exactly_one_permit_until_close() {
        // Mirrors the shared listener's CONNECTIONS bound (32); if the bound
        // changes, this test must be revisited together with loopback.rs.
        const CONNECTIONS: usize = 32;

        let (port, _stop) = bridge_port().await;
        let host = format!("localhost:{port}");
        let mut upgraded = Vec::with_capacity(CONNECTIONS);
        for _ in 0..CONNECTIONS {
            let (stream, head) = raw_upgrade(port, &host, None).await;
            assert!(head.starts_with("HTTP/1.1 101"), "{head}");
            upgraded.push(stream);
        }
        // The 33rd session waits for a permit; its handshake is never answered.
        let mut excess = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        excess
            .write_all(format!("GET /bridge HTTP/1.1\r\nHost: {host}\r\nOrigin: http://localhost:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let answered = read_head(&mut excess, Duration::from_millis(800)).await;
        assert!(
            answered.is_none(),
            "a 33rd upgraded connection was admitted beyond the bound"
        );
        // Closing one upgraded session releases exactly its one permit.
        drop(upgraded.remove(0));
        let head = read_head(&mut excess, Duration::from_secs(3))
            .await
            .expect("the excess connection admitted after a session closed");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    }

    #[tokio::test]
    async fn stalled_authentication_sessions_drain_and_release_shared_permits() {
        const CONNECTIONS: usize = 32;
        let (port, _stop) = bridge_port().await;
        let host = format!("localhost:{port}");
        let mut stalled = Vec::new();
        for _ in 0..CONNECTIONS {
            let (stream, head) = raw_upgrade(port, &host, None).await;
            assert!(head.starts_with("HTTP/1.1 101"), "{head}");
            stalled.push(stream);
        }
        let mut excess = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect excess");
        excess
            .write_all(format!("GET /bridge HTTP/1.1\r\nHost: {host}\r\nOrigin: http://localhost:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes())
            .await
            .expect("write excess upgrade");
        assert!(
            read_head(&mut excess, Duration::from_millis(500))
                .await
                .is_none(),
            "32 stalled upgraded connections consume the shared cap"
        );
        let head = read_head(&mut excess, AUTH_DEADLINE + Duration::from_secs(2))
            .await
            .expect("stalled auth deadlines release permits");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        drop(stalled);
    }

    #[tokio::test]
    async fn upgraded_sessions_draw_from_the_same_bounded_pool_as_http() {
        const CONNECTIONS: usize = 32;

        let (port, _stop) = bridge_port().await;
        let host = format!("localhost:{port}");
        let mut upgraded = Vec::with_capacity(CONNECTIONS);
        for _ in 0..CONNECTIONS {
            let (stream, head) = raw_upgrade(port, &host, None).await;
            assert!(head.starts_with("HTTP/1.1 101"), "{head}");
            upgraded.push(stream);
        }
        // A plain HTTP request waits for the same pool: not answered.
        let mut http = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        http.write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("write");
        let answered = read_head(&mut http, Duration::from_millis(800)).await;
        assert!(
            answered.is_none(),
            "a plain HTTP connection was admitted beyond the bound"
        );
        drop(upgraded.remove(0));
        let head = read_head(&mut http, Duration::from_secs(3))
            .await
            .expect("the HTTP connection admitted after a session closed");
        assert_eq!(status_code(&head), 404);
    }

    #[tokio::test]
    async fn bridge_sessions_retire_on_daemon_stop() {
        // S-02.4: the listener stop token reaches upgraded WebSocket
        // sessions; the session closes with 1001 Away, releasing its
        // admission permit.
        let (port, stop) = bridge_port().await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        stop.cancel();
        let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("close frame within budget")
            .expect("stream ended before a frame arrived")
            .expect("frame failed to decode");
        match message {
            Message::Close(Some(frame)) => {
                assert_eq!(frame.code, CloseCode::Away, "daemon stop closes with 1001")
            }
            other => panic!("expected a close frame, got {other:?}"),
        }
    }

    /// A padding upgrade/HTTP header field, sized so the total head crosses
    /// the 4096-byte mark while staying far under `HEAD_LIMIT` (8192).
    fn big_value(bytes: usize) -> String {
        "a".repeat(bytes)
    }

    #[tokio::test]
    async fn a_large_plain_http_head_is_served_byte_identically() {
        // WDA-WI-08 probe bound: a head of 4097–8192 bytes must still be
        // served by the listener, not closed by the probe (regression for
        // the 4096-byte buffer that made such heads unservable).
        let (port, _stop) = bridge_port().await;
        let padding = big_value(5000);
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nX-Big: {padding}\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .expect("write head");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            stream
                .read_to_end(&mut response)
                .await
                .expect("read response");
        })
        .await
        .expect("response within budget");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        assert!(response.trim_end().ends_with("fallback"), "{response}");
    }

    #[tokio::test]
    async fn an_unterminated_head_past_the_limit_is_closed() {
        // The probe closes a connection whose head never completes within
        // the listener's head discipline (8192 bytes, five seconds) — the
        // same closing behavior hyper's header timeout applies for plain
        // HTTP, now covering the bridge path too.
        let (port, _stop) = bridge_port().await;
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        let line = format!("X-Fill: {}\r\n", big_value(512));
        let mut request = String::with_capacity(8192 + line.len());
        request.push_str("GET / HTTP/1.1\r\nHost: localhost\r\n");
        while request.len() < 8192 {
            request.push_str(&line);
        }
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write head");
        let mut buffer = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
            .await
            .expect("peer close within budget");
        match read {
            // The server drops the connection without a response: a clean
            // EOF, or a reset because the kernel had unread client bytes.
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("expected the connection to be closed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_large_ws_upgrade_head_completes_the_101_and_the_session() {
        // The same regression for the bridge path: a /bridge WS upgrade
        // whose total head crosses 4096 bytes must still complete the
        // handshake and run a session frame.
        let (port, _stop) = bridge_port().await;
        let padding = big_value(5000);
        let host = format!("localhost:{port}");
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        let request = format!(
            "GET /bridge HTTP/1.1\r\nHost: {host}\r\nOrigin: http://localhost:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {RFC_KEY}\r\nSec-WebSocket-Version: 13\r\nX-Big: {padding}\r\n\r\n"
        );
        assert!(
            request.len() > 4096,
            "head must exceed the old 4096-byte probe cap"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write head");
        let head = read_head(&mut stream, Duration::from_secs(2))
            .await
            .expect("response head within budget");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        // The session is live: a WS client frame gets a WS response... the
        // simplest deterministic proof is the daemon-stop close.
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            stream,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        ws.send(auth_text("test-token", 1))
            .await
            .expect("send auth");
        expect_silence(&mut ws, "large-upgrade-head session after auth").await;
    }

    fn mock_host_adapter() -> (
        tauri::App<tauri::test::MockRuntime>,
        std::sync::Arc<dyn InvocationAdapter>,
    ) {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        let app = mock_builder()
            .manage(crate::pairing::Pairing::default())
            .build(mock_context(noop_assets()))
            .expect("mock host app");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        (app, adapter)
    }

    #[tokio::test]
    async fn state_command_round_trips_through_the_live_bridge() {
        use tauri::Manager as _;
        let (app, adapter) = mock_host_adapter();
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let desktop_result = crate::pairing::pairing_status(app.state(), "missing-id".into())
            .expect("desktop-equivalent State command");
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 7)))
            .await
            .expect("State auth send deadline")
            .expect("auth");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                1,
                "pairing_status",
                serde_json::json!({"kind":"json","value":{"id":"missing-id"}}),
            )),
        )
        .await
        .expect("State invoke send deadline")
        .expect("State invoke");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("State response deadline")
            .expect("State response frame")
            .expect("State response decode");
        let Message::Text(response) = response else {
            panic!("expected State JSON result, got {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).expect("JSON response");
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["id"], 1);
        assert_eq!(
            response["payload"],
            serde_json::to_value(desktop_result).unwrap()
        );
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("State close deadline")
            .expect("close State socket");
    }

    #[tokio::test]
    async fn plugin_shell_catalog_and_change_round_trip_with_real_manager() {
        use tauri::test::{mock_builder, mock_context, noop_assets};

        async fn plugin_bridge_call(
            ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            id: u64,
            command: &str,
            body: Value,
        ) -> Value {
            tokio::time::timeout(
                Duration::from_secs(2),
                ws.send(invoke_text(id, command, body)),
            )
            .await
            .expect("plugin invoke send deadline")
            .expect("plugin invoke send");
            let response = tokio::time::timeout(Duration::from_secs(3), ws.next())
                .await
                .expect("plugin response deadline")
                .expect("plugin response frame")
                .expect("plugin response websocket");
            serde_json::from_str(response.to_text().expect("JSON response")).unwrap()
        }

        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let manager =
            buzzodz_plugins::Manager::open(Some(root.clone()), "bridge-plugin-shell", false)
                .unwrap();
        let direct = manager.catalog().unwrap();
        let direct_ids = direct
            .plugins
            .iter()
            .map(|plugin| plugin.manifest.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for id in ["buzz.pi", "buzz.goose", "block.builderlab"] {
            assert!(direct_ids.contains(id), "manager catalog missing {id}");
        }
        let app = mock_builder()
            .manage(crate::PluginManager(Ok(manager.clone())))
            .manage(crate::federated_identity::access::Registrations::default())
            .build(mock_context(noop_assets()))
            .expect("plugin shell fixture app");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 82)))
            .await
            .expect("plugin auth deadline")
            .expect("plugin auth");
        let catalog = plugin_bridge_call(
            &mut ws,
            1,
            "plugin_catalog",
            serde_json::json!({"kind":"json","value":{}}),
        )
        .await;
        assert_eq!(catalog["type"], "invoke_ok", "{catalog}");
        let catalog = &catalog["payload"]["catalog"]["plugins"];
        for id in ["buzz.pi", "buzz.goose", "block.builderlab"] {
            assert!(
                catalog
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|plugin| plugin["manifest"]["id"] == id),
                "bridge catalog missing {id}: {catalog}"
            );
        }
        let before = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|plugin| plugin["manifest"]["id"] == "buzz.channels")
            .unwrap()["enabled"]
            .as_bool()
            .unwrap();
        let changed = plugin_bridge_call(
            &mut ws,
            2,
            "plugin_change",
            serde_json::json!({"kind":"json","value":{"action":if before {"disable"} else {"enable"},"id":"buzz.channels"}}),
        )
        .await;
        assert_eq!(changed["type"], "invoke_err");
        assert!(changed["error"].as_str().unwrap().contains("required"));
        let pi_enabled = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|plugin| plugin["manifest"]["id"] == "buzz.pi")
            .unwrap()["enabled"]
            .as_bool()
            .unwrap();
        let changed = plugin_bridge_call(
            &mut ws,
            3,
            "plugin_change",
            serde_json::json!({"kind":"json","value":{"action":if pi_enabled {"disable"} else {"enable"},"id":"buzz.pi"}}),
        )
        .await;
        assert_eq!(changed["type"], "invoke_ok", "{changed}");
        assert_eq!(
            changed["payload"]["catalog"]["plugins"]
                .as_array()
                .unwrap()
                .iter()
                .find(|plugin| plugin["manifest"]["id"] == "buzz.pi")
                .unwrap()["enabled"],
            !pi_enabled
        );
        std::fs::write(
            root.join("profiles/bridge-plugin-shell/registry.json"),
            b"{corrupt",
        )
        .unwrap();
        let recovery = plugin_bridge_call(
            &mut ws,
            4,
            "plugin_catalog",
            serde_json::json!({"kind":"json","value":{}}),
        )
        .await;
        assert_eq!(recovery["type"], "invoke_ok", "{recovery}");
        assert_eq!(recovery["payload"]["status"], "recovery");
        assert_eq!(recovery["payload"]["canReset"], true);
        if buzzodz_plugins::managed::PACKAGED_URL.is_empty() {
            let refreshed = plugin_bridge_call(
                &mut ws,
                5,
                "plugin_managed_refresh",
                serde_json::json!({"kind":"json","value":{}}),
            )
            .await;
            assert_eq!(refreshed["type"], "invoke_ok", "{refreshed}");
            assert_eq!(refreshed["payload"]["status"], "recovery");
            assert_eq!(refreshed["payload"]["canReset"], true);
        }
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("plugin close deadline")
            .expect("plugin close");
    }

    #[tokio::test]
    async fn identity_create_and_import_round_trip_with_identity_service_fixtures() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;

        async fn bridge_call(
            ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            id: u64,
            command: &str,
            body: Value,
        ) -> Value {
            tokio::time::timeout(
                Duration::from_secs(2),
                ws.send(invoke_text(id, command, body)),
            )
            .await
            .expect("identity invoke send deadline")
            .expect("identity invoke send");
            let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .expect("identity response deadline")
                .expect("identity response frame")
                .expect("identity response websocket");
            serde_json::from_str(response.to_text().expect("JSON response"))
                .unwrap_or_else(|error| panic!("valid response JSON {response:?}: {error}"))
        }

        let created_app_for_bridge = mock_builder()
            .manage(crate::identity::tests::bridge_fixture())
            .manage(crate::nsec_backup::NsecBackupHost::default())
            .build(mock_context(noop_assets()))
            .expect("bridge identity create fixture app");
        let create_adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            created_app_for_bridge.handle().clone(),
        ));
        let (create_port, _create_stop) = bridge_port_with_adapter(Some(create_adapter)).await;
        let mut create_ws = ws_client(create_port, None).await;
        create_ws
            .send(auth_text("test-token", 90))
            .await
            .expect("create auth");
        let created = bridge_call(
            &mut create_ws,
            1,
            "identity_create",
            serde_json::json!({"kind":"json","value":{}}),
        )
        .await;
        assert_eq!(created["type"], "invoke_ok");
        let created_viewer: String = serde_json::from_value(created["payload"].clone()).unwrap();
        assert_eq!(created_viewer.len(), 64);
        assert!(created_viewer.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            crate::identity::identity_restore(
                created_app_for_bridge.state::<crate::identity::IdentityHost>()
            )
            .await
            .unwrap(),
            Some(created_viewer),
        );
        create_ws.close(None).await.expect("close create bridge");

        let nsec = crate::identity::tests::test_nsec();
        let direct_app = mock_builder()
            .manage(crate::identity::tests::bridge_fixture())
            .manage(crate::nsec_backup::NsecBackupHost::default())
            .build(mock_context(noop_assets()))
            .expect("desktop identity import fixture app");
        let expected_import = crate::identity::identity_import(
            direct_app.state::<crate::identity::IdentityHost>(),
            direct_app.state::<crate::nsec_backup::NsecBackupHost>(),
            nsec.clone(),
        )
        .await
        .expect("desktop import fixture succeeds");

        // Use a fresh fixture for the bridge call; both invoke the production identity service.
        let import_host = crate::identity::tests::bridge_fixture();
        let app = mock_builder()
            .manage(import_host.clone())
            .manage(crate::nsec_backup::NsecBackupHost::default())
            .build(mock_context(noop_assets()))
            .expect("identity import fixture app");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        ws.send(auth_text("test-token", 91)).await.expect("auth");
        let imported_response = bridge_call(
            &mut ws,
            1,
            "identity_import",
            serde_json::json!({"kind":"json","value":{"nsec": nsec}}),
        )
        .await;
        assert_eq!(imported_response["type"], "invoke_ok");
        assert_eq!(imported_response["payload"], expected_import);

        let expected_import_occupied = crate::identity::identity_import(
            app.state::<crate::identity::IdentityHost>(),
            app.state::<crate::nsec_backup::NsecBackupHost>(),
            nsec.clone(),
        )
        .await
        .expect_err("desktop import refuses an occupied identity slot");
        let import_occupied = bridge_call(
            &mut ws,
            2,
            "identity_import",
            serde_json::json!({"kind":"json","value":{"nsec": nsec}}),
        )
        .await;
        assert_eq!(import_occupied["type"], "invoke_err");
        assert_eq!(
            import_occupied["error"],
            expected_import_occupied.to_string()
        );

        // The imported key now occupies the slot: creation must preserve the same
        // error returned by the desktop command instead of replacing it.
        let expected_occupied = crate::identity::identity_create(
            app.state::<crate::identity::IdentityHost>(),
            app.state::<crate::nsec_backup::NsecBackupHost>(),
        )
        .await
        .expect_err("create refuses an occupied identity slot");
        let occupied = bridge_call(
            &mut ws,
            2,
            "identity_create",
            serde_json::json!({"kind":"json","value":{}}),
        )
        .await;
        assert_eq!(occupied["type"], "invoke_err");
        assert_eq!(occupied["error"], expected_occupied.to_string());

        ws.close(None).await.expect("close identity bridge");
    }

    #[tokio::test]
    async fn identity_agent_state_and_direct_message_commands_round_trip_through_bridge() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;
        let temp = tempfile::tempdir().expect("agent state temp directory");
        let identity = crate::identity::IdentityHost::fixture();
        let app = mock_builder()
            .manage(crate::pairing::Pairing::default())
            .manage(identity.clone())
            .manage(crate::federated_identity::FederatedIdentity::unconfigured())
            .manage(crate::agent_state::AgentState::new(Ok(temp
                .path()
                .to_owned())))
            .build(mock_context(noop_assets()))
            .expect("headless turn fixture");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let desktop_identity = crate::identity::identity_restore(app.state())
            .await
            .expect("same identity service as desktop");
        let desktop_set = crate::agent_state::app_agent_state_set(
            app.state(),
            "turn.fixture".into(),
            Some("ready".into()),
            None,
        )
        .await
        .expect("same agent-state setter as desktop");
        let desktop_load = crate::agent_state::app_agent_state_load(app.state(), None)
            .await
            .expect("same agent-state loader as desktop");
        let desktop_dm_error = crate::relay::relay_direct_message(
            app.state(),
            app.state(),
            "https://relay.example".into(),
            Vec::new(),
        )
        .await
        .expect_err("empty direct-message membership is refused before relay I/O");

        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 17)))
            .await
            .expect("turn auth send deadline")
            .expect("auth");
        for (id, command, body, expected_type, expected_payload) in [
            (
                1,
                "identity_restore",
                serde_json::json!({"kind":"json","value":{}}),
                "invoke_ok",
                serde_json::to_value(desktop_identity).unwrap(),
            ),
            (
                2,
                "app_agent_state_set",
                serde_json::json!({"kind":"json","value":{"key":"turn.fixture","value":"ready"}}),
                "invoke_ok",
                serde_json::to_value(desktop_set).unwrap(),
            ),
            (
                3,
                "app_agent_state_load",
                serde_json::json!({"kind":"json","value":{}}),
                "invoke_ok",
                serde_json::to_value(desktop_load).unwrap(),
            ),
            (
                4,
                "relay_direct_message",
                serde_json::json!({"kind":"json","value":{"community":"https://relay.example","pubkeys":[]}}),
                "invoke_err",
                serde_json::to_value(desktop_dm_error).unwrap(),
            ),
        ] {
            tokio::time::timeout(
                Duration::from_secs(2),
                ws.send(invoke_text(id, command, body)),
            )
            .await
            .unwrap_or_else(|_| panic!("{command} invoke send deadline"))
            .unwrap_or_else(|_| panic!("{command} invoke send"));
            let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap_or_else(|_| panic!("{command} response deadline"))
                .expect("response frame")
                .expect("response decode");
            let Message::Text(response) = response else {
                panic!("expected {command} JSON response, got {response:?}")
            };
            let response: Value = serde_json::from_str(response.as_str()).expect("JSON response");
            assert_eq!(response["type"], expected_type, "{command}");
            assert_eq!(response["id"], id, "{command}");
            let actual_payload = if response["type"] == "invoke_ok" {
                &response["payload"]
            } else {
                &response["error"]
            };
            assert_eq!(actual_payload, &expected_payload, "{command}");
        }
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("turn bridge close deadline")
            .expect("close turn bridge socket");
    }

    struct AgentTestCredentials(std::sync::Mutex<std::collections::HashMap<String, String>>);

    impl buzz_agent_controller::Credentials for AgentTestCredentials {
        fn read_legacy(
            &self,
            _: buzz_agent_controller::LegacySource,
            _: &str,
        ) -> Result<buzz_agent_controller::Secret, String> {
            Err("legacy credentials unavailable in fixture".into())
        }

        fn read(
            &self,
            _: &str,
            pubkey: &str,
        ) -> Result<Option<buzz_agent_controller::Secret>, String> {
            self.0
                .lock()
                .unwrap()
                .get(pubkey)
                .map(|secret| buzz_agent_controller::Secret::parse(secret, pubkey))
                .transpose()
        }

        fn add(&self, _: &str, secret: &buzz_agent_controller::Secret) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .insert(secret.pubkey().to_owned(), secret.hex().to_string());
            Ok(())
        }

        fn delete(&self, _: &str, pubkey: &str) -> Result<(), String> {
            self.0.lock().unwrap().remove(pubkey);
            Ok(())
        }
    }

    #[tokio::test]
    async fn agent_create_and_list_round_trip_through_bridge() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;

        let temp = tempfile::tempdir().expect("agent storage temp directory");
        let identity = crate::identity::IdentityHost::fixture();
        let owner = identity
            .saved_viewer()
            .await
            .expect("test identity loads")
            .expect("fixture contains a real identity");
        let credentials = Arc::new(AgentTestCredentials(std::sync::Mutex::default()));
        let agents = crate::app_agents::AppAgentHost::new(
            Ok(temp.path().join("agents.json")),
            Err("unused legacy agent store".into()),
            true,
            crate::federated_identity::agent::AgentTokens::unconfigured(),
        )
        .with_credentials_for_test(credentials);
        let app = mock_builder()
            .manage(identity)
            .manage(agents)
            .manage(crate::federated_identity::FederatedIdentity::unconfigured())
            .build(mock_context(noop_assets()))
            .expect("headless agent fixture");
        let adapter = Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let destination = "https://relay.example.test".to_owned();
        let agent_type = "pi".to_owned();
        let name = "Bridge-created agent".to_owned();

        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 27)))
            .await
            .expect("agent auth send deadline")
            .expect("auth");
        for (id, command, body) in [
            (
                1,
                "app_agent_create",
                serde_json::json!({
                    "kind":"json",
                    "value":{
                        "destination":destination,
                        "owner":owner,
                        "agentType":agent_type,
                        "name":name
                    }
                }),
            ),
            (
                2,
                "app_agent_list",
                serde_json::json!({"kind":"json","value":{}}),
            ),
        ] {
            tokio::time::timeout(
                Duration::from_secs(2),
                ws.send(invoke_text(id, command, body)),
            )
            .await
            .unwrap_or_else(|_| panic!("{command} invoke send deadline"))
            .unwrap_or_else(|_| panic!("{command} invoke send"));
            let response = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .unwrap_or_else(|_| panic!("{command} response deadline"))
                .expect("response frame")
                .expect("response decode");
            let Message::Text(response) = response else {
                panic!("expected {command} JSON result, got {response:?}")
            };
            let response: Value = serde_json::from_str(response.as_str()).expect("JSON response");
            assert_eq!(response["type"], "invoke_ok", "{command}: {response}");
            assert_eq!(response["id"], id, "{command}");
            if command == "app_agent_create" {
                assert_eq!(response["payload"]["owner"], owner);
                assert_eq!(response["payload"]["type"], agent_type);
                assert_eq!(response["payload"]["name"], name);
                assert!(response["payload"]["pubkey"].as_str().is_some());
            } else {
                let listed = crate::app_agents::app_agent_list(app.state())
                    .await
                    .expect("desktop-equivalent agent list");
                assert_eq!(response["payload"], serde_json::to_value(listed).unwrap());
                assert_eq!(response["payload"].as_array().unwrap().len(), 1);
                assert_eq!(response["payload"][0]["name"], name);
            }
        }
        let expected_library = crate::relay::relay_agent_library(
            app.state(),
            app.state(),
            "https://relay.example.test".into(),
        )
        .await
        .expect("desktop-equivalent agent library");
        tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(
            3, "relay_agent_library", serde_json::json!({"kind":"json","value":{"community":"https://relay.example.test"}}),
        ))).await.expect("library invoke send deadline").expect("library invoke send");
        let response = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("library response deadline")
            .expect("library response")
            .expect("library decode");
        let Message::Text(response) = response else {
            panic!("expected library JSON result: {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).unwrap();
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["id"], 3);
        assert_eq!(
            response["payload"],
            serde_json::to_value(expected_library).unwrap()
        );

        let channel_template = serde_json::json!({
            "kind": 9002, "created_at": 1_700_000_010, "content": "",
            "tags": [["h", uuid::Uuid::new_v4().to_string()], ["name", "Records"], ["about", ""], ["visibility", "open"]]
        });
        let expected_signed = crate::relay::relay_channel_sign(
            app.state(),
            "https://relay.example.test".into(),
            "channel-details".into(),
            channel_template.clone(),
        )
        .await
        .expect("desktop-equivalent channel sign");
        tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(
            4, "relay_channel_sign", serde_json::json!({"kind":"json","value":{
                "community":"https://relay.example.test", "route":"channel-details", "event":channel_template
            }}),
        ))).await.expect("channel sign invoke send deadline").expect("channel sign invoke send");
        let response = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("channel sign response deadline")
            .expect("channel sign response")
            .expect("channel sign decode");
        let Message::Text(response) = response else {
            panic!("expected channel sign JSON result: {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).unwrap();
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["id"], 4);
        let expected_signed = serde_json::to_value(expected_signed).unwrap();
        for field in ["content", "created_at", "id", "kind", "pubkey", "tags"] {
            assert_eq!(
                response["payload"][field], expected_signed[field],
                "channel sign {field}"
            );
        }
        assert!(response["payload"]["sig"].as_str().is_some());

        let expected_legacy = crate::legacy_communities::legacy_communities()
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                5,
                "legacy_communities",
                serde_json::json!({"kind":"json","value":{}}),
            )),
        )
        .await
        .expect("legacy invoke send deadline")
        .expect("legacy invoke send");
        let response = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("legacy response deadline")
            .expect("legacy response")
            .expect("legacy decode");
        let Message::Text(response) = response else {
            panic!("expected legacy JSON result: {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).unwrap();
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["id"], 5);
        assert_eq!(
            response["payload"],
            serde_json::to_value(expected_legacy).unwrap()
        );

        let memory_args =
            serde_json::json!({"community":"not a URL", "agent":"a".repeat(64), "slug":null});
        let expected_memory_error = crate::relay::agent::relay_agent_memories_read_headless(
            app.state::<crate::identity::IdentityHost>().inner(),
            app.state::<crate::federated_identity::FederatedIdentity>()
                .inner(),
            memory_args["community"].as_str().unwrap().to_owned(),
            memory_args["agent"].as_str().unwrap().to_owned(),
            None,
        )
        .await
        .unwrap_err();
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                6,
                "relay_agent_memories_read",
                serde_json::json!({"kind":"json","value":memory_args}),
            )),
        )
        .await
        .expect("memory invoke send deadline")
        .expect("memory invoke send");
        let response = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("memory response deadline")
            .expect("memory response")
            .expect("memory decode");
        let Message::Text(response) = response else {
            panic!("expected memory error response: {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).unwrap();
        assert_eq!(response["type"], "invoke_err");
        assert_eq!(response["id"], 6);
        assert_eq!(response["error"], expected_memory_error);

        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("agent bridge close deadline")
            .expect("close agent bridge socket");
    }

    #[tokio::test]
    async fn relay_agent_memories_read_returns_real_memory_through_live_bridge() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;

        let community = crate::federated_identity::testing::community(false).await;
        let owner = community.host.viewer().await.expect("fixture owner");
        let agent_key = buzz_agent_controller::Secret::generate().expect("agent test key");
        let agent = agent_key.pubkey().to_owned();
        let memory = agent_key
            .memory_event(&owner, "core", Some("bridge memory fixture"), 1_700_000_001)
            .expect("signed memory event");
        let wire = serde_json::json!([memory]).to_string();
        let relay_responses = community.serve_dynamic(2, move |_, _| {
            crate::federated_identity::testing::reply("200 OK", &wire)
        });
        let origin = community.origin.origin().ascii_serialization();
        let app = mock_builder()
            .manage(community.host.clone())
            .manage(community.fi.clone())
            .build(mock_context(noop_assets()))
            .expect("headless memory-read app");
        let adapter = Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;

        let direct = crate::relay::agent::relay_agent_memories_read_headless(
            app.state::<crate::identity::IdentityHost>().inner(),
            app.state::<crate::federated_identity::FederatedIdentity>()
                .inner(),
            origin.clone(),
            agent.clone(),
            Some("core".into()),
        )
        .await
        .expect("direct fixture memory read");
        assert_eq!(direct["entries"][0]["body"], "bridge memory fixture");

        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 47)))
            .await
            .expect("memory auth deadline")
            .expect("memory auth");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                1,
                "relay_agent_memories_read",
                serde_json::json!({"kind":"json","value":{
                    "community":origin, "agent":agent, "slug":"core"
                }}),
            )),
        )
        .await
        .expect("memory invoke send deadline")
        .expect("memory invoke send");
        let response = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("memory bridge response deadline")
            .expect("memory bridge response")
            .expect("memory response decode");
        let Message::Text(response) = response else {
            panic!("expected memory JSON response: {response:?}")
        };
        let response: Value =
            serde_json::from_str(response.as_str()).expect("memory JSON response");
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["id"], 1);
        assert_eq!(response["payload"], direct);
        assert_eq!(
            response["payload"]["entries"][0]["body"],
            "bridge memory fixture"
        );
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("memory bridge close deadline")
            .expect("close memory bridge socket");
        let heads = relay_responses.heads().await;
        assert_eq!(
            heads.len(),
            2,
            "direct and bridged memory reads reach relay"
        );
    }

    #[tokio::test]
    async fn agent_custody_and_identity_commands_round_trip_through_bridge() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;

        let community = crate::federated_identity::testing::community(false).await;
        let response = community.serve_dynamic(1, |_, body| {
            let event: Value = serde_json::from_slice(body).expect("signed agent event");
            crate::federated_identity::testing::reply(
                "200 OK",
                &serde_json::json!({"accepted":true,"event_id":event["id"]}).to_string(),
            )
        });
        let relay = community.origin.origin().ascii_serialization();
        let owner = community.host.viewer().await.expect("owner identity");
        let temp = tempfile::tempdir().expect("agent storage temp directory");
        let credentials = Arc::new(AgentTestCredentials(std::sync::Mutex::default()));
        let agents = crate::app_agents::AppAgentHost::new(
            Ok(temp.path().join("agents.json")),
            Err("unused legacy agent store".into()),
            true,
            crate::federated_identity::agent::AgentTokens::unconfigured(),
        )
        .with_credentials_for_test(credentials);
        let app = mock_builder()
            .manage(community.host.clone())
            .manage(community.fi.clone())
            .manage(agents)
            .build(mock_context(noop_assets()))
            .expect("headless agent custody app");
        let adapter = Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 38)))
            .await
            .expect("agent auth send deadline")
            .expect("auth");

        async fn invoke(
            ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            id: u64,
            command: &str,
            value: Value,
        ) -> Value {
            tokio::time::timeout(
                Duration::from_secs(2),
                ws.send(invoke_text(
                    id,
                    command,
                    serde_json::json!({"kind":"json","value":value}),
                )),
            )
            .await
            .unwrap_or_else(|_| panic!("{command} send deadline"))
            .unwrap_or_else(|_| panic!("{command} send"));
            let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
                .await
                .unwrap_or_else(|_| panic!("{command} response deadline"))
                .expect("response frame")
                .expect("response decode");
            let Message::Text(frame) = frame else {
                panic!("expected {command} response, got {frame:?}")
            };
            let response: Value = serde_json::from_str(frame.as_str()).expect("JSON response");
            assert_eq!(response["type"], "invoke_ok", "{command}: {response}");
            assert_eq!(response["id"], id);
            response["payload"].clone()
        }

        let created = invoke(
            &mut ws,
            1,
            "app_agent_create",
            serde_json::json!({"destination":relay,"owner":owner,"agentType":"pi","name":"Custody round trip"}),
        )
        .await;
        let pubkey = created["pubkey"]
            .as_str()
            .expect("created public key")
            .to_owned();
        assert_eq!(created["type"], "pi");
        assert_eq!(
            invoke(
                &mut ws,
                2,
                "app_agent_set_picture",
                serde_json::json!({"pubkey":pubkey,"relay":relay,"picture":"https://example.test/default-avatar.png"}),
            )
            .await,
            Value::Null
        );
        assert_eq!(
            invoke(
                &mut ws,
                3,
                "app_agent_claim",
                serde_json::json!({"pubkey":pubkey,"revision":0}),
            )
            .await,
            Value::Bool(true),
            "runner acquires custody before its turn"
        );
        let published = invoke(
            &mut ws,
            4,
            "app_agent_publish",
            serde_json::json!({"pubkey":pubkey,"relay":relay,"event":{"kind":9,"content":"agent reply","tags":[]}}),
        )
        .await;
        assert_eq!(published["content"], "agent reply");
        assert_eq!(published["pubkey"], pubkey);
        assert_eq!(
            invoke(
                &mut ws,
                5,
                "app_agent_release",
                serde_json::json!({"pubkey":pubkey}),
            )
            .await,
            Value::Null
        );
        assert_eq!(
            crate::app_agents::app_agent_claim(app.state(), pubkey, Some(0))
                .await
                .expect("released custody can be claimed"),
            true,
            "release relinquishes custody"
        );
        crate::app_agents::app_agent_release(
            app.state(),
            created["pubkey"].as_str().unwrap().into(),
        );
        let request_heads = tokio::time::timeout(Duration::from_secs(5), response.heads())
            .await
            .expect("publish request recorded");
        assert_eq!(request_heads.len(), 1);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("agent bridge close deadline")
            .expect("close agent bridge socket");
    }

    #[tokio::test]
    async fn agent_tool_commands_round_trip_through_bridge() {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;

        let community = crate::federated_identity::testing::community(false).await;
        let blob = b"tiny";
        let media_hash = format!("{:x}", Sha256::digest(blob));
        let response = community.serve_dynamic(7, move |head, body| {
            let path = head.split_whitespace().nth(1).expect("request path");
            let answer = match path {
                "/query" => crate::federated_identity::testing::reply(
                    "200 OK",
                    r#"[{"id":"query-event","kind":9,"content":"read"}]"#,
                ),
                "/events" => {
                    let event: Value = serde_json::from_slice(body).expect("signed event");
                    crate::federated_identity::testing::reply(
                        "200 OK",
                        &serde_json::json!({"accepted":true,"event_id":event["id"]}).to_string(),
                    )
                }
                "/upload" => crate::federated_identity::testing::reply(
                    "200 OK",
                    r#"{"url":"https://community.test/media/receipt"}"#,
                ),
                "/profiles/search" => crate::federated_identity::testing::reply(
                    "200 OK",
                    r#"[{"id":"profile-event","kind":0}]"#,
                ),
                path if path.starts_with("/media/") => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    blob.len(),
                    String::from_utf8_lossy(blob),
                ),
                _ => panic!("unexpected agent tool request: {head}"),
            };
            answer
        });
        let relay = community.origin.origin().ascii_serialization();
        let owner = community.host.viewer().await.expect("owner identity");
        let temp = tempfile::tempdir().expect("agent storage directory");
        let credentials = Arc::new(AgentTestCredentials(std::sync::Mutex::default()));
        let agents = crate::app_agents::AppAgentHost::new(
            Ok(temp.path().join("agents.json")),
            Err("unused legacy agent store".into()),
            true,
            crate::federated_identity::agent::AgentTokens::unconfigured(),
        )
        .with_credentials_for_test(credentials);
        let app = mock_builder()
            .manage(community.host.clone())
            .manage(community.fi.clone())
            .manage(agents)
            .build(mock_context(noop_assets()))
            .expect("headless agent tool app");
        let adapter = Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 39)))
            .await
            .expect("agent tool auth deadline")
            .expect("auth");

        async fn invoke(
            ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            id: u64,
            command: &str,
            value: Value,
        ) -> Value {
            tokio::time::timeout(
                Duration::from_secs(2),
                ws.send(invoke_text(
                    id,
                    command,
                    serde_json::json!({"kind":"json","value":value}),
                )),
            )
            .await
            .unwrap_or_else(|_| panic!("{command} send deadline"))
            .unwrap_or_else(|_| panic!("{command} send"));
            let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
                .await
                .unwrap_or_else(|_| panic!("{command} response deadline"))
                .expect("response frame")
                .expect("response decode");
            let Message::Text(frame) = frame else {
                panic!("expected {command} response, got {frame:?}")
            };
            let response: Value = serde_json::from_str(frame.as_str()).expect("JSON response");
            assert_eq!(response["type"], "invoke_ok", "{command}: {response}");
            assert_eq!(response["id"], id);
            response["payload"].clone()
        }
        let created = invoke(
            &mut ws,
            1,
            "app_agent_create",
            serde_json::json!({"destination":relay,"owner":owner,"agentType":"pi","name":"Tool-path agent"}),
        )
        .await;
        let pubkey = created["pubkey"].as_str().expect("agent pubkey").to_owned();
        assert_eq!(
            invoke(
                &mut ws,
                2,
                "app_agent_claim",
                serde_json::json!({"pubkey":pubkey,"revision":0}),
            )
            .await,
            Value::Bool(true)
        );

        let filters = vec![serde_json::json!({"kinds":[9],"limit":1})];
        let desktop_query = crate::app_agents::app_agent_query(
            app.state(),
            pubkey.clone(),
            relay.clone(),
            filters.clone(),
        )
        .await
        .expect("desktop-equivalent agent query");
        let queried = invoke(
            &mut ws,
            3,
            "app_agent_query",
            serde_json::json!({"pubkey":pubkey,"relay":relay,"filters":filters}),
        )
        .await;
        assert_eq!(queried, desktop_query);
        assert_eq!(queried[0]["id"], "query-event");
        assert_eq!(queried[0]["kind"], 9);
        let desktop_query_error = crate::app_agents::app_agent_query(
            app.state(),
            pubkey.clone(),
            relay.clone(),
            Vec::new(),
        )
        .await
        .expect_err("desktop refuses an empty query");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                11,
                "app_agent_query",
                serde_json::json!({"kind":"json","value":{"pubkey":pubkey,"relay":relay,"filters":[]}}),
            )),
        )
        .await
        .expect("invalid query send deadline")
        .expect("invalid query send");
        let error_frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("invalid query response deadline")
            .expect("invalid query response")
            .expect("decode invalid query response");
        let Message::Text(error_frame) = error_frame else {
            panic!("expected invalid query error frame, got {error_frame:?}")
        };
        let error_frame: Value = serde_json::from_str(error_frame.as_str()).expect("error JSON");
        assert_eq!(error_frame["type"], "invoke_err");
        assert_eq!(error_frame["error"], desktop_query_error);
        let remembered = invoke(
            &mut ws,
            4,
            "app_agent_remember",
            serde_json::json!({"pubkey":pubkey,"relay":relay,"slug":"core","body":"remembered fact","after":0}),
        )
        .await;
        assert_eq!(remembered["kind"], 30174);
        assert_eq!(remembered["pubkey"], pubkey);
        let upload = invoke(
            &mut ws,
            5,
            "app_agent_upload",
            serde_json::json!({"pubkey":pubkey,"relay":relay,"data":base64::engine::general_purpose::STANDARD.encode(blob),"mime":"image/png"}),
        )
        .await;
        assert_eq!(upload["url"], "https://community.test/media/receipt");
        let media = invoke(
            &mut ws,
            6,
            "app_agent_media",
            serde_json::json!({"pubkey":pubkey,"relay":relay,"url":format!("{media_hash}.png")}),
        )
        .await;
        assert_eq!(media["type"], "image/png");
        assert_eq!(media["size"], blob.len());
        assert_eq!(
            media["data"],
            base64::engine::general_purpose::STANDARD.encode(blob)
        );
        let git = invoke(
            &mut ws,
            7,
            "app_agent_git_auth",
            serde_json::json!({"pubkey":pubkey,"relay":relay,"owner":owner,"repo":"example-repo"}),
        )
        .await;
        assert!(git["url"].as_str().unwrap().contains("/example-repo.git"));
        assert!(git["header"]
            .as_str()
            .unwrap()
            .starts_with("Authorization: Nostr "));
        let profiles = invoke(
            &mut ws,
            8,
            "app_agent_search_profiles",
            serde_json::json!({"pubkey":pubkey,"relay":relay,"query":"example","limit":5}),
        )
        .await;
        assert_eq!(profiles[0]["id"], "profile-event");
        assert_eq!(
            invoke(
                &mut ws,
                9,
                "app_agent_publish_profile",
                serde_json::json!({"pubkey":pubkey,"relay":relay,"force":true}),
            )
            .await,
            Value::Null
        );
        assert_eq!(
            invoke(
                &mut ws,
                10,
                "app_agent_release",
                serde_json::json!({"pubkey":pubkey}),
            )
            .await,
            Value::Null
        );
        assert!(
            crate::app_agents::app_agent_claim(app.state(), pubkey.clone(), Some(0))
                .await
                .expect("released agent can be claimed again")
        );
        crate::app_agents::app_agent_release(app.state(), pubkey);
        let heads = tokio::time::timeout(Duration::from_secs(5), response.heads())
            .await
            .expect("all bounded tool requests served");
        assert_eq!(heads.len(), 7);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("tool bridge close deadline")
            .expect("close tool bridge");
    }

    #[tokio::test]
    async fn direct_message_open_success_round_trips_through_bridge() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;
        let community = crate::federated_identity::testing::community(false).await;
        let origin = community.origin.origin().ascii_serialization();
        let peer = nostr::key::Keys::generate().public_key().to_hex();
        let channel_id = "11111111-1111-4111-8111-111111111111";
        let server = community.serve_dynamic(2, move |_, body| {
            let event: Value = serde_json::from_slice(body).expect("posted direct-message event");
            let receipt = serde_json::json!({
                "accepted": true,
                "event_id": event["id"],
                "message": format!("response:{}", serde_json::json!({"channel_id":channel_id})),
            });
            crate::federated_identity::testing::reply("200 OK", &receipt.to_string())
        });
        let app = mock_builder()
            .manage(crate::identity::IdentityHost::fixture())
            .manage(community.fi.clone())
            .build(mock_context(noop_assets()))
            .expect("headless direct-message app");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let peers = vec![peer];
        let desktop = crate::relay::relay_direct_message(
            app.state(),
            app.state(),
            origin.clone(),
            peers.clone(),
        )
        .await
        .expect("desktop-equivalent successful direct-message open");
        assert_eq!(desktop, channel_id);
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 21)))
            .await
            .expect("DM auth send deadline")
            .expect("auth");
        tokio::time::timeout(
            Duration::from_secs(5),
            ws.send(invoke_text(
                1,
                "relay_direct_message",
                serde_json::json!({"kind":"json","value":{"community":origin,"pubkeys":peers}}),
            )),
        )
        .await
        .expect("DM invoke send deadline")
        .expect("DM invoke");
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("DM response deadline")
            .expect("DM response frame")
            .expect("DM response decode");
        let Message::Text(message) = message else {
            panic!("expected DM JSON response, got {message:?}")
        };
        let message: Value = serde_json::from_str(message.as_str()).expect("JSON response");
        assert_eq!(message["type"], "invoke_ok");
        assert_eq!(message["id"], 1);
        assert_eq!(message["payload"], desktop);
        let requests = tokio::time::timeout(Duration::from_secs(5), server.heads())
            .await
            .expect("direct-message relay fixture deadline");
        assert_eq!(requests.len(), 2);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("DM bridge close deadline")
            .expect("close DM bridge socket");
    }

    #[tokio::test]
    async fn relay_writer_and_keep_awake_commands_round_trip_through_bridge() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;
        let app = mock_builder()
            .manage(crate::identity::IdentityHost::fixture())
            .manage(crate::federated_identity::FederatedIdentity::unconfigured())
            .manage(crate::keep_awake::KeepAwake::default())
            .build(mock_context(noop_assets()))
            .expect("headless writer fixture");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let template = || crate::identity::EventTemplate {
            kind: 9,
            created_at: 1_700_000_000,
            content: "bridge writer proof".into(),
            tags: Vec::new(),
        };
        let desktop_event =
            crate::relay::relay_sign(app.state(), "https://relay.example".into(), template())
                .await
                .expect("desktop-equivalent relay signer");
        let claims = serde_json::json!([{
            "id": desktop_event["id"],
            "pubkey": desktop_event["pubkey"],
            "sig": desktop_event["sig"]
        }]);
        let desktop_claims =
            serde_json::from_value::<Vec<crate::relay::SignatureClaim>>(claims.clone())
                .expect("signature claims deserialize");
        let desktop_verified = crate::relay::relay_verify_signatures(desktop_claims)
            .await
            .expect("desktop-equivalent signature verifier");
        let desktop_awake = crate::keep_awake::keep_awake_set(app.state(), false)
            .expect("desktop-equivalent keep-awake release");

        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 18)))
            .await
            .expect("writer auth send deadline")
            .expect("auth");
        let calls = [
            (
                1,
                "relay_sign",
                serde_json::json!({"kind":"json","value":{"community":"https://relay.example","event":template()}}),
                serde_json::to_value(desktop_event).unwrap(),
            ),
            (
                2,
                "relay_verify_signatures",
                serde_json::json!({"kind":"json","value":{"claims":claims}}),
                serde_json::to_value(desktop_verified).unwrap(),
            ),
            (
                3,
                "keep_awake_set",
                serde_json::json!({"kind":"json","value":{"hold":false}}),
                serde_json::to_value(desktop_awake).unwrap(),
            ),
        ];
        for (id, command, body, expected) in calls {
            tokio::time::timeout(
                Duration::from_secs(2),
                ws.send(invoke_text(id, command, body)),
            )
            .await
            .unwrap_or_else(|_| panic!("{command} invoke send deadline"))
            .unwrap_or_else(|_| panic!("{command} invoke send"));
            let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap_or_else(|_| panic!("{command} response deadline"))
                .expect("response frame")
                .expect("response decode");
            let Message::Text(response) = response else {
                panic!("expected {command} JSON response, got {response:?}")
            };
            let response: Value = serde_json::from_str(response.as_str()).expect("JSON response");
            assert_eq!(response["type"], "invoke_ok", "{command}");
            assert_eq!(response["id"], id, "{command}");
            if command == "relay_sign" {
                for field in ["content", "created_at", "id", "kind", "pubkey", "tags"] {
                    assert_eq!(
                        response["payload"][field], expected[field],
                        "relay_sign {field}"
                    );
                }
                assert!(
                    response["payload"]["sig"].as_str().is_some(),
                    "relay_sign returns a signature"
                );
            } else {
                assert_eq!(response["payload"], expected, "{command}");
            }
        }
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("writer bridge close deadline")
            .expect("close writer bridge socket");
    }

    #[tokio::test]
    async fn relay_http_request_used_by_writer_publish_round_trips_through_bridge() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;
        let community = crate::federated_identity::testing::community(false).await;
        let response = crate::federated_identity::testing::reply(
            "200 OK",
            r#"{"accepted":true,"event_id":"bridge-event"}"#,
        );
        let server = community.serve(vec![response.clone(), response]);
        let event_body = serde_json::json!({
            "id":"bridge-event", "pubkey":"01".repeat(32), "kind":9,
            "created_at":1_700_000_000, "content":"outbox publish", "tags":[]
        })
        .to_string();
        let origin = community.origin.origin().ascii_serialization();
        let app = mock_builder()
            .manage(crate::identity::IdentityHost::fixture())
            .manage(community.fi.clone())
            .build(mock_context(noop_assets()))
            .expect("headless relay HTTP fixture");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let desktop = crate::relay::relay_http(
            app.state(),
            app.state(),
            origin.clone(),
            "/events".into(),
            "POST".into(),
            Some(event_body.clone()),
            None,
        )
        .await
        .expect("desktop-equivalent GET");
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 19)))
            .await
            .expect("relay HTTP auth send deadline")
            .expect("auth");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                1,
                "relay_http",
                serde_json::json!({"kind":"json","value":{"community":origin,"path":"/events","method":"POST","body":event_body,"id":null}}),
            )),
        )
        .await
        .expect("relay HTTP invoke send deadline")
        .expect("relay HTTP invoke");
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("relay HTTP response deadline")
            .expect("relay HTTP response frame")
            .expect("relay HTTP response decode");
        let Message::Text(message) = message else {
            panic!("expected relay HTTP JSON response, got {message:?}")
        };
        let message: Value = serde_json::from_str(message.as_str()).expect("JSON response");
        assert_eq!(message["type"], "invoke_ok");
        assert_eq!(message["id"], 1);
        assert_eq!(message["payload"], serde_json::to_value(desktop).unwrap());
        let heads = tokio::time::timeout(Duration::from_secs(5), server.heads())
            .await
            .expect("relay fixture served both direct and bridge requests");
        assert_eq!(heads.len(), 2);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("relay HTTP bridge close deadline")
            .expect("close relay HTTP bridge socket");
    }

    #[tokio::test]
    async fn relay_socket_commands_round_trip_and_channel_delivers_events() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tauri::test::{mock_builder, mock_context, noop_assets};
        let community = crate::federated_identity::testing::community(true).await;
        let relay_url = format!("wss://{}", community.origin.authority());
        let mut server = Some(community.serve_socket(|mut relay| async move {
            // A burst from the relay exercises the continuous stream rather
            // than only one callback at a time.
            for data in ["burst-0", "burst-1", "burst-2"] {
                relay
                    .send(Message::text(format!(r#"["NOTICE","{data}"]"#)))
                    .await
                    .expect("send relay burst message");
            }
            // Several ordered client sends exercise the same production
            // socket send queue as desktop.
            for expected in ["send-0", "send-1", "send-2"] {
                let sent = tokio::time::timeout(Duration::from_secs(5), relay.next())
                    .await
                    .expect("relay send frame deadline")
                    .expect("relay send frame")
                    .expect("relay send decode");
                assert_eq!(sent, Message::text(format!(r#"["EVENT","{expected}"]"#)));
            }
            relay
                .send(Message::text(r#"["NOTICE","after-send"]"#))
                .await
                .expect("send final relay message");
            let _ = tokio::time::timeout(Duration::from_secs(5), relay.next()).await;
        }));
        struct RelayStop(Option<tokio::task::JoinHandle<String>>);
        impl Drop for RelayStop {
            fn drop(&mut self) {
                if let Some(task) = self.0.take() {
                    task.abort();
                }
            }
        }
        let mut server = RelayStop(server.take());
        let app = mock_builder()
            .manage(crate::federated_identity::socket::Sockets::default())
            .manage(community.fi.clone())
            .manage(community.host.clone())
            .build(mock_context(noop_assets()))
            .expect("headless relay socket app");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _bridge_stop) = bridge_port_with_adapter(Some(adapter)).await;
        // Model the callback id allocated by the browser's Channel. It must
        // survive connect and be used for every envelope on the stream.
        let callback = CALLBACK_NAMESPACE_MIN + 1234;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 20)))
            .await
            .expect("socket auth send deadline")
            .expect("auth");

        async fn invoke_result(
            ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            id: u64,
            command: &str,
            body: Value,
        ) -> Value {
            tokio::time::timeout(
                Duration::from_secs(5),
                ws.send(invoke_text(id, command, body)),
            )
            .await
            .unwrap_or_else(|_| panic!("{command} send deadline"))
            .unwrap_or_else(|_| panic!("{command} send"));
            for _ in 0..8 {
                let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
                    .await
                    .unwrap_or_else(|_| panic!("{command} response deadline"))
                    .expect("response frame")
                    .expect("response decode");
                let Message::Text(text) = message else {
                    continue;
                };
                let response: Value = serde_json::from_str(text.as_str()).expect("JSON frame");
                if response["type"] == "invoke_ok" && response["id"] == id {
                    return response["payload"].clone();
                }
                assert_ne!(response["type"], "invoke_err", "{command}: {response}");
            }
            panic!("{command} response was not observed within eight bridge frames");
        }
        let mode = invoke_result(
            &mut ws,
            1,
            "relay_socket_connect",
            serde_json::json!({"kind":"json","value":{"id":"11111111-1111-4111-8111-111111111111","relay":relay_url,"onEvent":format!("__CHANNEL__:{callback}")}}),
        )
        .await;
        assert_eq!(mode, "native");
        invoke_result(
            &mut ws,
            2,
            "relay_socket_start",
            serde_json::json!({"kind":"json","value":{"id":"11111111-1111-4111-8111-111111111111"}}),
        )
        .await;
        let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("first callback deadline")
            .expect("first callback")
            .expect("first callback decode");
        let Message::Text(first) = first else {
            panic!("expected callback")
        };
        let first: Value = serde_json::from_str(first.as_str()).expect("callback JSON");
        assert_eq!(first["type"], "callback");
        assert_eq!(first["id"], callback);
        assert_eq!(first["envelope"]["index"], 0);
        assert_eq!(first["envelope"]["message"]["type"], "text");
        assert_eq!(
            first["envelope"]["message"]["data"],
            r#"["NOTICE","burst-0"]"#
        );
        for (index, expected) in [(1, "burst-1"), (2, "burst-2")] {
            let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("burst callback deadline")
                .expect("burst callback")
                .expect("burst callback decode");
            let Message::Text(frame) = frame else {
                panic!("expected callback")
            };
            let frame: Value = serde_json::from_str(frame.as_str()).expect("callback JSON");
            assert_eq!(frame["type"], "callback");
            assert_eq!(frame["id"], callback, "delivery must use client Channel id");
            assert_eq!(frame["envelope"]["index"], index);
            assert_eq!(
                frame["envelope"]["message"]["data"],
                format!(r#"["NOTICE","{expected}"]"#)
            );
        }

        for (invoke_id, data) in [(3, "send-0"), (4, "send-1"), (5, "send-2")] {
            invoke_result(
                &mut ws,
                invoke_id,
                "relay_socket_send",
                serde_json::json!({"kind":"json","value":{"id":"11111111-1111-4111-8111-111111111111","data":format!(r#"["EVENT","{data}"]"#)}}),
            )
            .await;
        }
        let second = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("final callback deadline")
            .expect("final callback")
            .expect("final callback decode");
        let Message::Text(second) = second else {
            panic!("expected callback")
        };
        let second: Value = serde_json::from_str(second.as_str()).expect("callback JSON");
        assert_eq!(second["id"], callback);
        assert_eq!(second["envelope"]["index"], 3);
        assert_eq!(
            second["envelope"]["message"]["data"],
            r#"["NOTICE","after-send"]"#
        );

        invoke_result(
            &mut ws,
            6,
            "relay_socket_close",
            serde_json::json!({"kind":"json","value":{"id":"11111111-1111-4111-8111-111111111111"}}),
        )
        .await;
        let task = server.0.take().expect("relay task");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("relay shutdown deadline")
            .expect("relay fixture join");
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("socket bridge close deadline")
            .expect("close socket bridge");
    }

    #[tokio::test]
    async fn authorized_plugin_directory_command_round_trips_and_denial_matches_dispatcher() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let manager =
            buzzodz_plugins::Manager::open(Some(root.join("registry")), "test", false).unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("plugin.js"), "export function apply() {}\n").unwrap();
        std::fs::write(
            source.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "id":"bridge.files", "name":"Bridge files", "apiVersion":1,
                "host":{"files":true}
            }))
            .unwrap(),
        )
        .unwrap();
        buzzodz_plugins::sign_release(&source, &nostr::key::SecretKey::generate().to_secret_hex())
            .unwrap();
        let catalog = manager.install(&source).unwrap();
        let revision = catalog
            .plugins
            .iter()
            .find(|p| p.manifest.id == "bridge.files")
            .unwrap()
            .revision
            .clone();
        manager.change("enable", "bridge.files").unwrap();
        let denied_source = root.join("denied-source");
        std::fs::create_dir(&denied_source).unwrap();
        std::fs::write(
            denied_source.join("plugin.js"),
            "export function apply() {}\\n",
        )
        .unwrap();
        std::fs::write(
            denied_source.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "id":"bridge.denied", "name":"Bridge denied", "apiVersion":1,
                "host":{"files":false}
            }))
            .unwrap(),
        )
        .unwrap();
        buzzodz_plugins::sign_release(
            &denied_source,
            &nostr::key::SecretKey::generate().to_secret_hex(),
        )
        .unwrap();
        let denied_catalog = manager.install(&denied_source).unwrap();
        let denied_revision = denied_catalog
            .plugins
            .iter()
            .find(|p| p.manifest.id == "bridge.denied")
            .unwrap()
            .revision
            .clone();
        manager.change("enable", "bridge.denied").unwrap();
        let app = mock_builder()
            .manage(crate::PluginManager(Ok(manager.clone())))
            .build(mock_context(noop_assets()))
            .expect("headless mock app");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let directory = root.join("real-directory");
        std::fs::create_dir(&directory).unwrap();
        let body = serde_json::json!({"kind":"json","value":{"id":"bridge.files","revision":revision,"path":directory.to_str().unwrap(),"create":false}});
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 9)))
            .await
            .expect("plugin auth deadline")
            .expect("auth");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                3,
                "plugin_host_resolve_directory",
                body.clone(),
            )),
        )
        .await
        .expect("plugin invoke deadline")
        .expect("invoke");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("plugin response deadline")
            .expect("response")
            .expect("decode");
        let Message::Text(response) = response else {
            panic!("expected plugin result: {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).unwrap();
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["payload"], directory.to_str().unwrap());
        // The same command reached through the stock dispatcher rejects an
        // undeclared files grant before touching its path.
        let denied = crate::host_files::plugin_host_resolve_directory(
            app.state(),
            "bridge.denied".into(),
            denied_revision.clone(),
            directory.to_str().unwrap().into(),
            Some(false),
        )
        .await
        .unwrap_err();
        assert_eq!(denied, "Files are not declared");
        let denied_body = serde_json::json!({"kind":"json","value":{"id":"bridge.denied","revision":denied_revision,"path":directory.to_str().unwrap(),"create":false}});
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(4, "plugin_host_resolve_directory", denied_body)),
        )
        .await
        .expect("denied invoke deadline")
        .expect("denied invoke");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("denied response deadline")
            .expect("denied response")
            .expect("denied decode");
        let Message::Text(response) = response else {
            panic!("expected denial: {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).unwrap();
        assert_eq!(response["type"], "invoke_err");
        assert_eq!(response["error"], denied);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("plugin close deadline")
            .expect("close");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn plugin_process_commands_round_trip_through_real_host_processes() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        let temp = tempfile::tempdir().expect("process fixture directory");
        let root = dunce::canonicalize(temp.path()).unwrap();
        let credentials = crate::credential_service::tests::fixture();
        let plugin_id = credentials
            .agent
            .agent_type
            .split_once('/')
            .expect("fixture agent plugin type")
            .0
            .to_owned();
        let manager =
            buzzodz_plugins::Manager::open(Some(root.join("registry")), "test", false).unwrap();
        let source = root.join("process-plugin");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("plugin.js"), "export function apply() {}\\n").unwrap();
        std::fs::write(source.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
            "id":plugin_id, "name":"Bridge process", "apiVersion":1,
            "host":{"processes":[{"id":"echo","program":"sh"},{"id":"cat","program":"cat"},{"id":"sleep","program":"sleep"}]}
        })).unwrap()).unwrap();
        buzzodz_plugins::sign_release(&source, &nostr::key::SecretKey::generate().to_secret_hex())
            .unwrap();
        let catalog = manager.install(&source).unwrap();
        let revision = catalog
            .plugins
            .iter()
            .find(|p| p.manifest.id == plugin_id)
            .unwrap()
            .revision
            .clone();
        manager.change("enable", &plugin_id).unwrap();
        let app = mock_builder()
            .manage(crate::PluginManager(Ok(manager)))
            .manage(crate::host_process::HostProcesses::default())
            .manage(credentials.service.clone())
            .build(mock_context(noop_assets()))
            .expect("headless process app");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 31)))
            .await
            .unwrap()
            .unwrap();

        async fn invoke(
            ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            id: u64,
            cmd: &str,
            value: Value,
        ) -> Value {
            tokio::time::timeout(
                Duration::from_secs(3),
                ws.send(invoke_text(
                    id,
                    cmd,
                    serde_json::json!({"kind":"json","value":value}),
                )),
            )
            .await
            .unwrap_or_else(|_| panic!("{cmd} send deadline"))
            .unwrap_or_else(|_| panic!("{cmd} send"));
            loop {
                let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
                    .await
                    .unwrap_or_else(|_| panic!("{cmd} response deadline"))
                    .expect("frame")
                    .expect("decode");
                let Message::Text(frame) = frame else {
                    continue;
                };
                let value: Value = serde_json::from_str(frame.as_str()).unwrap();
                if value["id"] == id {
                    if value["type"] == "invoke_ok" {
                        return value["payload"].clone();
                    }
                    if value["type"] == "invoke_err" {
                        return serde_json::json!({"error": value["error"]});
                    }
                }
            }
        }
        async fn event(
            ws: &mut WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
            callback: u64,
        ) -> Value {
            loop {
                let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
                    .await
                    .expect("process event deadline")
                    .expect("process event")
                    .expect("decode");
                let Message::Text(frame) = frame else {
                    continue;
                };
                let value: Value = serde_json::from_str(frame.as_str()).unwrap();
                if value["type"] == "callback" && value["id"] == callback {
                    return value["envelope"]["message"].clone();
                }
            }
        }
        let callback = CALLBACK_NAMESPACE_MIN;
        let handle = invoke(&mut ws, 1, "plugin_host_process_spawn", serde_json::json!({
            "id":plugin_id,"revision":revision,"processId":"echo","args":["-c","printf 'OUT\\n'; printf 'ERR\\n' >&2; exit 7"],"cwd":null,"env":null,"mcp":null,"protection":null,"agentCredential":false,"protectedAgent":null,"secrets":[],"onEvent":null
        })).await;
        assert!(handle.as_u64().is_some());
        let mut output = Vec::new();
        loop {
            let message = event(&mut ws, callback).await;
            output.push(message.clone());
            if message["type"] == "exit" {
                break;
            }
        }
        assert!(
            output
                .iter()
                .any(|event| event == &serde_json::json!({"type":"stdout","data":"OUT\n"})),
            "events: {output:?}"
        );
        assert!(output
            .iter()
            .any(|event| event == &serde_json::json!({"type":"stderr","data":"ERR\n"})));
        assert!(output
            .iter()
            .any(|event| event == &serde_json::json!({"type":"exit","code":7})));

        let callback2 = CALLBACK_NAMESPACE_MIN + 1;
        let tool_pubkey = credentials.agent.pubkey.clone();
        let cat = invoke(&mut ws, 2, "plugin_host_process_spawn", serde_json::json!({
            "id":plugin_id,"revision":revision,"processId":"cat","args":[],"cwd":null,"env":null,"mcp":null,"protection":null,"agentCredential":true,"protectedAgent":null,"secrets":[],"onEvent":null
        })).await.as_u64().unwrap();
        assert_eq!(invoke(&mut ws, 3, "plugin_host_process_bind_agent", serde_json::json!({"id":plugin_id,"handle":cat,"pubkey":tool_pubkey,"relay":crate::credential_service::tests::RELAY})).await, Value::Null);
        assert!(invoke(&mut ws, 4, "plugin_host_process_tool_credential", serde_json::json!({"id":plugin_id,"handle":cat,"pubkey":tool_pubkey,"relay":crate::credential_service::tests::RELAY})).await.as_str().is_some());
        assert_eq!(
            invoke(
                &mut ws,
                5,
                "plugin_host_process_write",
                serde_json::json!({"id":plugin_id,"handle":cat,"data":"round-trip\\n","close":true})
            )
            .await,
            Value::Null
        );
        let echoed = event(&mut ws, callback2).await;
        assert_eq!(
            echoed,
            serde_json::json!({"type":"stdout","data":"round-trip\\n"})
        );
        let exit = event(&mut ws, callback2).await;
        assert_eq!(exit["type"], "exit");

        let sleeper = invoke(&mut ws, 6, "plugin_host_process_spawn", serde_json::json!({
            "id":plugin_id,"revision":revision,"processId":"sleep","args":["30"],"cwd":null,"env":null,"mcp":null,"protection":null,"agentCredential":false,"protectedAgent":null,"secrets":[],"onEvent":null
        })).await.as_u64().unwrap();
        assert_eq!(
            invoke(
                &mut ws,
                7,
                "plugin_host_process_kill",
                serde_json::json!({"id":plugin_id,"handle":sleeper})
            )
            .await,
            Value::Null
        );
        let killed_exit = event(&mut ws, CALLBACK_NAMESPACE_MIN + 5).await;
        assert_eq!(killed_exit["type"], "exit");
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn channel_sink_delivers_envelope_then_raw_binary_frame_in_order() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut ws = tokio::time::timeout(
                Duration::from_secs(2),
                tokio_tungstenite::accept_async(stream),
            )
            .await
            .unwrap()
            .unwrap();
            write_channel_delivery(
                &mut ws,
                CALLBACK_NAMESPACE_MIN + 17,
                4,
                &Value::Null,
                Some(b"raw-body"),
            )
            .await
            .expect("channel sink write");
        });
        let (mut client, _) = tokio::time::timeout(
            Duration::from_secs(2),
            tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}")),
        )
        .await
        .unwrap()
        .unwrap();
        let envelope = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Text(envelope) = envelope else {
            panic!("expected envelope before binary: {envelope:?}")
        };
        let envelope: Value = serde_json::from_str(envelope.as_str()).unwrap();
        assert_eq!(
            envelope["envelope"],
            serde_json::json!({"index":4,"message":null})
        );
        let frame = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Binary(frame) = frame else {
            panic!("expected raw binary frame: {frame:?}")
        };
        assert_eq!(
            decode_binary_frame(&frame).unwrap(),
            BinaryFrame::Channel {
                id: CALLBACK_NAMESPACE_MIN + 17,
                bytes: b"raw-body"
            }
        );
        tokio::time::timeout(Duration::from_secs(2), client.close(None))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn host_mcp_channel_reaches_real_bridge_client() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let manager =
            buzzodz_plugins::Manager::open(Some(root.join("registry")), "test", false).unwrap();
        let source = root.join("mcp-plugin");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("plugin.js"), "export function apply() {}\\n").unwrap();
        std::fs::write(
            source.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "id":"bridge.mcp", "name":"Bridge MCP", "apiVersion":1,
                "host":{"mcp":true}
            }))
            .unwrap(),
        )
        .unwrap();
        buzzodz_plugins::sign_release(&source, &nostr::key::SecretKey::generate().to_secret_hex())
            .unwrap();
        let catalog = manager.install(&source).unwrap();
        let revision = catalog
            .plugins
            .iter()
            .find(|p| p.manifest.id == "bridge.mcp")
            .unwrap()
            .revision
            .clone();
        manager.change("enable", "bridge.mcp").unwrap();
        let servers = crate::host_mcp::HostMcpServers::default();
        let app = mock_builder()
            .manage(crate::PluginManager(Ok(manager)))
            .manage(servers.clone())
            .build(mock_context(noop_assets()))
            .expect("headless mock app");
        struct McpStopGuard(crate::host_mcp::HostMcpServers);
        impl Drop for McpStopGuard {
            fn drop(&mut self) {
                self.0.stop_all();
            }
        }
        let _mcp_stop = McpStopGuard(servers);
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _bridge_stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 11)))
            .await
            .expect("MCP auth deadline")
            .expect("auth");
        tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(5, "plugin_host_mcp_serve", serde_json::json!({"kind":"json","value":{"id":"bridge.mcp","revision":revision,"sharedSession":false,"onEvent":format!("__CHANNEL__:{}",MAX_WIRE_ID - 17)}})))).await.expect("MCP serve invoke deadline").expect("invoke");
        let start = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("MCP serve response deadline")
            .expect("serve response")
            .expect("decode");
        let Message::Text(start) = start else {
            panic!("expected MCP serve result: {start:?}")
        };
        let start: Value = serde_json::from_str(start.as_str()).unwrap();
        assert_eq!(start["type"], "invoke_ok");
        let info = &start["payload"];
        let client = reqwest::Client::new();
        let request = client
            .post(info["url"].as_str().unwrap())
            .bearer_auth(info["token"].as_str().unwrap())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
        let pending_http = tokio::spawn(async move { request.send().await });
        let delivery = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("MCP event deadline")
            .expect("MCP event")
            .expect("MCP event decode");
        let Message::Text(delivery) = delivery else {
            panic!("expected typed MCP callback: {delivery:?}")
        };
        let delivery: Value = serde_json::from_str(delivery.as_str()).unwrap();
        assert_eq!(delivery["type"], "callback");
        assert_eq!(delivery["id"], MAX_WIRE_ID - 17);
        assert_eq!(delivery["envelope"]["index"], 0);
        assert_eq!(delivery["envelope"]["message"]["type"], "message");
        let forwarded: Value =
            serde_json::from_str(delivery["envelope"]["message"]["body"].as_str().unwrap())
                .unwrap();
        assert_eq!(forwarded["method"], "ping");
        let request_id = delivery["envelope"]["message"]["request"].as_u64().unwrap();
        tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(6, "plugin_host_mcp_reply", serde_json::json!({"kind":"json","value":{"id":"bridge.mcp","handle":info["handle"],"request":request_id,"body":null}}))))
            .await.expect("MCP reply invoke deadline").expect("MCP reply invoke");
        let reply_response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("MCP reply response deadline")
            .expect("MCP reply response")
            .expect("decode");
        let Message::Text(reply_response) = reply_response else {
            panic!("expected MCP reply response: {reply_response:?}")
        };
        let reply_response: Value = serde_json::from_str(reply_response.as_str()).unwrap();
        assert_eq!(reply_response["type"], "invoke_ok");
        assert_eq!(reply_response["payload"], Value::Null);
        let http = tokio::time::timeout(Duration::from_secs(2), pending_http)
            .await
            .expect("MCP HTTP completion deadline")
            .unwrap()
            .unwrap();
        assert_eq!(http.status(), reqwest::StatusCode::ACCEPTED);
        let second = client
            .post(info["url"].as_str().unwrap())
            .bearer_auth(info["token"].as_str().unwrap())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({"jsonrpc":"2.0","id":2,"method":"ping"}));
        let second_http = tokio::spawn(async move { second.send().await });
        let second_delivery = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("second MCP event deadline")
            .expect("second MCP event")
            .expect("second event decode");
        let Message::Text(second_delivery) = second_delivery else {
            panic!("expected second callback: {second_delivery:?}")
        };
        let second_delivery: Value = serde_json::from_str(second_delivery.as_str()).unwrap();
        assert_eq!(second_delivery["id"], delivery["id"]);
        assert_eq!(second_delivery["envelope"]["index"], 1);
        let second_request = second_delivery["envelope"]["message"]["request"]
            .as_u64()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(7, "plugin_host_mcp_reply", serde_json::json!({"kind":"json","value":{"id":"bridge.mcp","handle":info["handle"],"request":second_request,"body":null}}))))
            .await.expect("second MCP reply invoke deadline").expect("second MCP reply invoke");
        let reply_response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("second MCP reply response deadline")
            .expect("second MCP reply response")
            .expect("decode");
        let Message::Text(reply_response) = reply_response else {
            panic!("expected MCP reply response: {reply_response:?}")
        };
        let reply_response: Value = serde_json::from_str(reply_response.as_str()).unwrap();
        assert_eq!(reply_response["type"], "invoke_ok");
        assert_eq!(reply_response["payload"], Value::Null);
        let second_response = tokio::time::timeout(Duration::from_secs(2), second_http)
            .await
            .expect("second HTTP deadline")
            .unwrap()
            .unwrap();
        assert_eq!(second_response.status(), reqwest::StatusCode::ACCEPTED);
        tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(8, "plugin_host_mcp_close", serde_json::json!({"kind":"json","value":{"id":"bridge.mcp","handle":info["handle"]}}))))
            .await.expect("MCP close invoke deadline").expect("MCP close invoke");
        let close_response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("MCP close response deadline")
            .expect("MCP close response")
            .expect("decode");
        let Message::Text(close_response) = close_response else {
            panic!("expected MCP close response: {close_response:?}")
        };
        let close_response: Value = serde_json::from_str(close_response.as_str()).unwrap();
        assert_eq!(close_response["type"], "invoke_ok");
        assert_eq!(close_response["payload"], Value::Null);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("MCP bridge close deadline")
            .expect("close");
    }

    #[tokio::test]
    async fn concurrent_producers_preserve_callback_fifo_order_on_the_live_bridge() {
        const PRODUCERS: usize = 4;
        const PER_PRODUCER: usize = 6;
        let publisher = crate::bridge_adapter::EventPublisher::default();
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("headless mock app");
        let fi = crate::federated_identity::FederatedIdentity::unconfigured();
        fi.watch(app.handle().clone(), publisher.clone());
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::with_publisher(
            app.handle().clone(),
            publisher.clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(auth_text("test-token", 101)),
        )
        .await
        .expect("burst auth send deadline")
        .expect("auth");
        let callback = CALLBACK_NAMESPACE_MIN + 91;
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                1,
                "plugin:event|listen",
                serde_json::json!({"kind":"json","value":{"event":"burst-event","target":{"kind":"Any"},"handler":callback}}),
            )),
        )
        .await
        .expect("burst listen send deadline")
        .expect("listen");
        let listen_response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("burst listen response deadline")
            .expect("listen response frame")
            .expect("listen response decode");
        let Message::Text(listen_response) = listen_response else {
            panic!("expected listen response, got {listen_response:?}");
        };
        assert_eq!(
            serde_json::from_str::<Value>(listen_response.as_str()).unwrap()["payload"],
            callback
        );

        // Each producer emits its own ordered sequence while racing the others.
        // Publisher registration locking assigns callback indices and enqueues
        // each delivery in one critical section; the real session writer must
        // therefore deliver one contiguous callback FIFO without interleaving
        // its frames or losing a producer's internal order.
        let start = Arc::new(std::sync::Barrier::new(PRODUCERS));
        let mut producers = Vec::new();
        for producer in 0..PRODUCERS {
            let publisher = publisher.clone();
            let start = start.clone();
            producers.push(tokio::task::spawn_blocking(move || {
                start.wait();
                for sequence in 0..PER_PRODUCER {
                    publisher.publish(
                        "burst-event",
                        serde_json::json!({"producer":producer,"sequence":sequence}),
                    );
                }
            }));
        }
        for producer in producers {
            tokio::time::timeout(Duration::from_secs(2), producer)
                .await
                .expect("producer completion deadline")
                .expect("producer task");
        }

        let total = PRODUCERS * PER_PRODUCER;
        let mut last_sequence = [None; PRODUCERS];
        for expected_index in 0..total {
            let frame = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap_or_else(|_| panic!("delivery {expected_index} deadline"))
                .expect("delivery stream ended")
                .expect("delivery decode");
            let Message::Text(frame) = frame else {
                panic!("expected callback text, got {frame:?}");
            };
            let frame: Value = serde_json::from_str(frame.as_str()).expect("callback JSON");
            assert_eq!(frame["type"], "callback");
            assert_eq!(frame["id"], callback);
            assert_eq!(frame["envelope"]["index"], expected_index);
            let payload = &frame["envelope"]["message"]["payload"];
            let producer = payload["producer"].as_u64().expect("producer index") as usize;
            let sequence = payload["sequence"].as_u64().expect("sequence index") as usize;
            assert!(producer < PRODUCERS);
            assert_eq!(sequence, last_sequence[producer].map_or(0, |last| last + 1));
            last_sequence[producer] = Some(sequence);
        }
        assert!(last_sequence
            .iter()
            .all(|sequence| *sequence == Some(PER_PRODUCER - 1)));
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("burst client close deadline")
            .expect("close");
    }

    #[tokio::test]
    async fn authenticated_connection_takeover_retires_prior_generation() {
        let publisher = crate::bridge_adapter::EventPublisher::default();
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("headless mock app");
        let fi = crate::federated_identity::FederatedIdentity::unconfigured();
        fi.watch(app.handle().clone(), publisher.clone());
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::with_publisher(
            app.handle().clone(),
            publisher,
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let callback = CALLBACK_NAMESPACE_MIN + 101;
        let generations = [50, 50, 2, 99]; // equal, then lower, then higher
        let mut current: Option<WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>> =
            None;

        for (step, generation) in generations.into_iter().enumerate() {
            let mut next = ws_client(port, None).await;
            tokio::time::timeout(
                Duration::from_secs(2),
                next.send(auth_text("test-token", generation)),
            )
            .await
            .expect("takeover auth send deadline")
            .expect("auth");
            if let Some(mut retired) = current.take() {
                expect_close_code(
                    &mut retired,
                    CloseCode::from(4001),
                    "new authenticated connection retires previous owner",
                )
                .await;
            }

            tokio::time::timeout(
                Duration::from_secs(2),
                next.send(invoke_text(
                    step as u64 + 1,
                    "plugin:event|listen",
                    serde_json::json!({"kind":"json","value":{"event":"federated-identity","target":{"kind":"Any"},"handler":callback}}),
                )),
            )
            .await
            .expect("takeover listen send deadline")
            .expect("listen");
            let response = tokio::time::timeout(Duration::from_secs(2), next.next())
                .await
                .expect("takeover listen response deadline")
                .expect("listen response")
                .expect("listen decode");
            let Message::Text(response) = response else {
                panic!("expected listen response, got {response:?}");
            };
            assert_eq!(
                serde_json::from_str::<Value>(response.as_str()).unwrap()["payload"],
                callback
            );

            fi.note_clock_offset(Some(step as i64 + 1));
            let event = tokio::time::timeout(Duration::from_secs(2), next.next())
                .await
                .expect("takeover event deadline")
                .expect("event frame")
                .expect("event decode");
            let Message::Text(event) = event else {
                panic!("expected event callback, got {event:?}");
            };
            let event: Value = serde_json::from_str(event.as_str()).expect("callback JSON");
            assert_eq!(event["type"], "callback");
            assert_eq!(event["id"], callback);
            assert_eq!(event["envelope"]["index"], 0);
            assert_eq!(
                event["envelope"]["message"]["payload"]["clockOffset"],
                step as i64 + 1
            );
            current = Some(next);
        }
        if let Some(mut ws) = current {
            tokio::time::timeout(Duration::from_secs(2), ws.close(None))
                .await
                .expect("current owner close deadline")
                .expect("close");
        }
    }

    #[tokio::test]
    async fn saturated_callback_queue_closes_bridge_visibly() {
        let publisher = crate::bridge_adapter::EventPublisher::default();
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("headless mock app");
        let fi = crate::federated_identity::FederatedIdentity::unconfigured();
        fi.watch(app.handle().clone(), publisher.clone());
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::with_publisher(
            app.handle().clone(),
            publisher.clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 77)))
            .await
            .expect("overload auth send deadline")
            .expect("auth");
        let callback = CALLBACK_NAMESPACE_MIN + 111;
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                1,
                "plugin:event|listen",
                serde_json::json!({"kind":"json","value":{"event":"overload-event","target":{"kind":"Any"},"handler":callback}}),
            )),
        )
        .await
        .expect("overload listen send deadline")
        .expect("listen");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("overload listen response deadline")
            .expect("listen response")
            .expect("listen decode");
        assert!(matches!(response, Message::Text(_)));

        // Produce far more events than the bounded 32-slot handoff can hold
        // without a reader. Saturation must retire the owning session and
        // surface the overload as a WebSocket policy close, never a silent
        // callback loss.
        let burst = tokio::task::spawn_blocking(move || {
            for index in 0..4096 {
                publisher.publish("overload-event", serde_json::json!({"n":index}));
            }
        });
        tokio::time::timeout(Duration::from_secs(2), burst)
            .await
            .expect("overload producer completion deadline")
            .expect("overload producer task");
        // Already-enqueued callbacks may precede the close on the wire. Drain
        // at most the 32-slot queue plus the one item the writer may have
        // dequeued when saturation occurred, requiring the visible close.
        let mut saw_close = false;
        for _ in 0..34 {
            let frame = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .expect("overload visibility frame deadline")
                .expect("overload closed without a WebSocket frame")
                .expect("overload WebSocket decode");
            match frame {
                Message::Close(Some(close)) => {
                    assert_eq!(close.code, CloseCode::Policy);
                    assert_eq!(close.reason, "delivery queue overloaded");
                    saw_close = true;
                    break;
                }
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(text.as_str()).unwrap();
                    assert_eq!(value["type"], "callback");
                }
                other => panic!("unexpected overload frame: {other:?}"),
            }
        }
        assert!(
            saw_close,
            "queue overload did not close the connection visibly"
        );
    }

    #[tokio::test]
    async fn event_listen_publish_unlisten_is_session_scoped_and_cleans_up_on_close() {
        let publisher = crate::bridge_adapter::EventPublisher::default();
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("headless mock app");
        let fi = crate::federated_identity::FederatedIdentity::unconfigured();
        fi.watch(app.handle().clone(), publisher.clone());
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::with_publisher(
            app.handle().clone(),
            publisher.clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let callback = CALLBACK_NAMESPACE_MIN + 71;
        let target = serde_json::json!({"kind":"Any"});
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 41)))
            .await
            .expect("event auth send deadline")
            .expect("auth");

        // Listen to the actual FI snapshot event emitted by the production producer.
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(2, "plugin:event|listen", serde_json::json!({"kind":"json","value":{"event":"federated-identity","target":{"kind":"Webview","label":"main"},"handler":callback}}))),
        )
        .await
        .expect("event listen send deadline")
        .expect("listen");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Text(response) = response else {
            panic!("expected listen result: {response:?}")
        };
        assert_eq!(
            serde_json::from_str::<Value>(response.as_str()).unwrap()["payload"],
            callback
        );
        assert_eq!(publisher.subscription_count(), 1);

        // This real FI snapshot mutation flows through FI::watch's production
        // publisher, while the existing desktop emit_to remains best-effort.
        fi.note_clock_offset(Some(3));
        let event = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Text(event) = event else {
            panic!("expected FI callback: {event:?}")
        };
        let event: Value = serde_json::from_str(event.as_str()).unwrap();
        assert_eq!(event["type"], "callback");
        assert_eq!(event["id"], callback);
        assert_eq!(event["envelope"]["index"], 0);
        assert_eq!(event["envelope"]["message"]["event"], "federated-identity");
        assert_eq!(event["envelope"]["message"]["id"], callback);
        assert_eq!(event["envelope"]["message"]["payload"]["clockOffset"], 3);

        // Exact pinned-api unlisten shape; repeating it is harmless.
        for invoke_id in [3, 4] {
            tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(invoke_id, "plugin:event|unlisten", serde_json::json!({"kind":"json","value":{"event":"federated-identity","eventId":callback}}))))
                .await
                .expect("unlisten send deadline")
                .expect("unlisten");
            let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let Message::Text(response) = response else {
                panic!("expected unlisten result: {response:?}")
            };
            assert_eq!(
                serde_json::from_str::<Value>(response.as_str()).unwrap()["type"],
                "invoke_ok"
            );
        }
        assert_eq!(publisher.subscription_count(), 0);
        fi.note_clock_offset(None);
        expect_silence(&mut ws, "delivery after idempotent unlisten").await;

        // Closing a connection drops its remaining registrations without browser unlisten.
        tokio::time::timeout(Duration::from_secs(2), ws.send(invoke_text(5, "plugin:event|listen", serde_json::json!({"kind":"json","value":{"event":"federated-identity","target":target,"handler":callback + 1}}))))
            .await
            .expect("cleanup listen send deadline")
            .expect("listen");
        let _ = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("cleanup listen response deadline")
            .expect("listen response")
            .expect("listen decode");
        assert_eq!(publisher.subscription_count(), 1);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("event client close deadline")
            .expect("close");
        tokio::time::timeout(Duration::from_secs(2), async {
            while publisher.subscription_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session close removes its subscription scope");
    }

    #[tokio::test]
    async fn raw_upload_chunk_round_trips_with_headers_and_binary_body() {
        let storage = tempfile::tempdir().expect("upload storage");
        let app = tauri::test::mock_builder()
            .manage(crate::relay::Uploads::default())
            .manage(crate::relay::Spools::new(Ok(storage.path().to_owned())))
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("headless upload app");
        let desktop_begin = tokio::time::timeout(
            Duration::from_secs(2),
            crate::relay::relay_upload_begin(app.handle().clone(), "desktop-chunk".into(), 6),
        )
        .await
        .expect("desktop upload begin deadline");
        let bridge_begin = tokio::time::timeout(
            Duration::from_secs(2),
            crate::relay::relay_upload_begin(app.handle().clone(), "bridge-chunk".into(), 6),
        )
        .await
        .expect("bridge upload begin deadline");
        assert_eq!(bridge_begin, desktop_begin);
        let desktop_result = tokio::time::timeout(
            Duration::from_secs(2),
            crate::relay::relay_upload_chunk_service(
                app.handle().clone(),
                Some("desktop-chunk"),
                Some("0"),
                Some(b"raw-by"),
            ),
        )
        .await
        .expect("desktop upload chunk deadline");
        let (port, _stop) = bridge_port_with_adapter(Some(std::sync::Arc::new(
            crate::bridge_adapter::HostAdapter::new(app.handle().clone()),
        )))
        .await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 31)))
            .await
            .expect("raw upload auth send deadline")
            .expect("raw upload auth");
        let invoke = serde_json::json!({
            "x-buzz-upload-id": "bridge-chunk",
            "x-buzz-upload-offset": "0",
            "content-type": "application/octet-stream"
        });
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text_with_headers(41, "relay_upload_chunk", invoke)),
        )
        .await
        .expect("raw upload invoke send deadline")
        .expect("raw upload invoke");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(Message::binary(b"raw-by".to_vec())),
        )
        .await
        .expect("raw upload body send deadline")
        .expect("raw upload body");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("raw upload response deadline")
            .expect("raw upload response frame")
            .expect("raw upload response decode");
        let Message::Text(response) = response else {
            panic!("expected raw upload JSON result, got {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).expect("raw upload result");
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["id"], 41);
        assert_eq!(
            response["payload"],
            serde_json::to_value(desktop_result.unwrap()).unwrap()
        );
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("raw upload close deadline")
            .expect("close raw upload socket");
    }

    #[tokio::test]
    async fn raw_file_response_round_trips_as_response_namespace_binary() {
        use tauri::test::{mock_builder, mock_context, noop_assets};
        use tauri::Manager as _;
        let temp = tempfile::tempdir().expect("plugin fixture root");
        let root = dunce::canonicalize(temp.path()).unwrap();
        let manager =
            buzzodz_plugins::Manager::open(Some(root.join("registry")), "test", false).unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("plugin.js"), "export function apply() {}\\n").unwrap();
        std::fs::write(
            source.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "id":"bridge.raw-files", "name":"Bridge raw files", "apiVersion":1,
                "host":{"files":true}
            }))
            .unwrap(),
        )
        .unwrap();
        buzzodz_plugins::sign_release(&source, &nostr::key::SecretKey::generate().to_secret_hex())
            .unwrap();
        let catalog = manager.install(&source).unwrap();
        let revision = catalog
            .plugins
            .iter()
            .find(|plugin| plugin.manifest.id == "bridge.raw-files")
            .unwrap()
            .revision
            .clone();
        manager.change("enable", "bridge.raw-files").unwrap();
        let file = root.join("real-payload.bin");
        let expected_bytes = b"headless plugin file bytes\\0\\xff";
        std::fs::write(&file, expected_bytes).unwrap();
        let app = mock_builder()
            .manage(crate::PluginManager(Ok(manager)))
            .build(mock_context(noop_assets()))
            .expect("headless raw response app");
        let desktop_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            crate::host_files::plugin_host_read_file_service(
                app.state(),
                "bridge.raw-files".into(),
                revision.clone(),
                file.to_string_lossy().into_owned(),
                None,
            ),
        )
        .await
        .expect("desktop file read deadline")
        .expect("desktop command's shared file service");
        let adapter = std::sync::Arc::new(crate::bridge_adapter::HostAdapter::new(
            app.handle().clone(),
        ));
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 32)))
            .await
            .expect("raw file auth send deadline")
            .expect("raw file auth");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                42,
                "plugin_host_read_file",
                serde_json::json!({
                    "kind":"json",
                    "value": {
                        "id":"bridge.raw-files",
                        "revision":revision,
                        "path":file.to_string_lossy()
                    }
                }),
            )),
        )
        .await
        .expect("raw file invoke send deadline")
        .expect("raw file invoke");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("raw file response deadline")
            .expect("raw file response frame")
            .expect("raw file response decode");
        let Message::Binary(frame) = response else {
            panic!("expected 0x01 raw response frame, got {response:?}")
        };
        assert_eq!(
            decode_binary_frame(&frame).expect("decode raw response"),
            BinaryFrame::Response {
                id: 42,
                bytes: &desktop_bytes,
            }
        );
        assert_eq!(desktop_bytes, expected_bytes);
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("raw file close deadline")
            .expect("close raw response socket");
    }

    #[tokio::test]
    async fn app_handle_command_round_trips_through_the_live_bridge() {
        let (app, adapter) = mock_host_adapter();
        let (port, _stop) = bridge_port_with_adapter(Some(adapter)).await;
        let desktop_result = crate::identity::identity_legacy_available(app.handle().clone());
        let mut ws = ws_client(port, None).await;
        tokio::time::timeout(Duration::from_secs(2), ws.send(auth_text("test-token", 8)))
            .await
            .expect("AppHandle auth send deadline")
            .expect("auth");
        tokio::time::timeout(
            Duration::from_secs(2),
            ws.send(invoke_text(
                2,
                "identity_legacy_available",
                serde_json::json!({"kind":"json","value":null}),
            )),
        )
        .await
        .expect("AppHandle invoke send deadline")
        .expect("AppHandle invoke");
        let response = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("AppHandle response deadline")
            .expect("AppHandle response frame")
            .expect("AppHandle response decode");
        let Message::Text(response) = response else {
            panic!("expected AppHandle JSON result, got {response:?}")
        };
        let response: Value = serde_json::from_str(response.as_str()).expect("JSON response");
        assert_eq!(response["type"], "invoke_ok");
        assert_eq!(response["id"], 2);
        assert_eq!(response["payload"], Value::Bool(desktop_result));
        tokio::time::timeout(Duration::from_secs(2), ws.close(None))
            .await
            .expect("AppHandle close deadline")
            .expect("close AppHandle socket");
    }
}
