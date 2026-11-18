//! Transport-aware host adapter for WDA-S-03.2. Each arm delegates to the
//! command's existing service function; transport supplies the app-managed
//! state and connection session context rather than going through Tauri's
//! webview-bound stock dispatcher.
use futures_util::future::BoxFuture;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex, Weak,
};
use tauri::{AppHandle, Manager, Runtime};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Private session owner identity. The auth-frame generation remains opaque;
/// this internal ID identifies one concrete bridge connection for takeover.
pub(crate) struct ConnectionOwner {
    id: u64,
    active: AtomicBool,
    cancellation: CancellationToken,
    close_kind: AtomicU8,
}

impl ConnectionOwner {
    fn new(id: u64) -> Self {
        Self {
            id,
            active: AtomicBool::new(false),
            cancellation: CancellationToken::new(),
            close_kind: AtomicU8::new(0),
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    pub(crate) fn cancel(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(crate) fn close_kind(&self) -> u8 {
        self.close_kind.load(Ordering::SeqCst)
    }

    fn retire(&self, kind: u8) {
        self.active.store(false, Ordering::SeqCst);
        let _ = self
            .close_kind
            .compare_exchange(0, kind, Ordering::SeqCst, Ordering::SeqCst);
        self.cancellation.cancel();
    }

    pub(crate) fn overload(&self) {
        self.retire(2);
    }
}

#[derive(Clone, Default)]
pub(crate) struct GenerationArbiter {
    state: Arc<Mutex<OwnerState>>,
    next_id: Arc<AtomicU64>,
}
#[derive(Default)]
struct OwnerState {
    active: Option<Arc<ConnectionOwner>>,
}

impl GenerationArbiter {
    pub(crate) fn new_connection(&self) -> Arc<ConnectionOwner> {
        let id = self
            .next_id
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        Arc::new(ConnectionOwner::new(id))
    }

    /// Linearizable takeover: invalidate and replace under one short lock;
    /// notify the retired owner only after releasing it.
    pub(crate) fn activate(&self, owner: &Arc<ConnectionOwner>) {
        let previous = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = state.active.replace(owner.clone());
            if let Some(previous) = &previous {
                previous.active.store(false, Ordering::SeqCst);
            }
            owner.active.store(true, Ordering::SeqCst);
            previous
        };
        if let Some(previous) = previous {
            previous.retire(1);
        }
    }

    pub(crate) fn is_current(&self, owner: &ConnectionOwner) -> bool {
        owner.is_active()
            && self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active
                .as_ref()
                .is_some_and(|active| active.id == owner.id)
    }
}

use crate::pairing::Pairing;

/// Authorization/session data supplied by the bridge after auth-first frame
/// parsing. Token validation and deadline enforcement remain WDA-WI-11.
#[derive(Clone)]
pub(crate) struct SessionContext {
    pub(crate) token: Zeroizing<String>,
    pub(crate) generation: u64,
}

/// A command response retains the distinction Tauri makes between JSON and raw IPC bytes.
pub(crate) enum AdapterResponse {
    Json(Value),
    Raw(Vec<u8>),
}

/// Normalized invoke input. Raw bodies and app headers are kept separate from
/// JSON arguments, matching Tauri's Request contract.
pub(crate) struct CommandInput {
    pub(crate) body: Value,
    pub(crate) raw_body: Option<Vec<u8>>,
    pub(crate) headers: Option<serde_json::Map<String, Value>>,
}

/// Per-connection adapter entrypoint. Its object-safe future lets the existing
/// WebSocket session call runtime-specific Tauri handles without a webview.
pub(crate) trait InvocationAdapter: Send + Sync {
    fn create_subscriptions(
        &self,
        deliveries: tokio::sync::mpsc::Sender<crate::bridge::ChannelDelivery>,
    ) -> Box<dyn SessionSubscriptions>;
    fn invoke(
        &self,
        command: String,
        input: CommandInput,
        context: SessionContext,
        callback_id: u64,
        deliveries: tokio::sync::mpsc::Sender<crate::bridge::ChannelDelivery>,
        owner: Arc<ConnectionOwner>,
    ) -> BoxFuture<'static, Result<AdapterResponse, Value>>;
}

pub(crate) trait SessionSubscriptions: Send {
    fn listen(
        &mut self,
        event: &str,
        target: &Value,
        handler: u64,
        generation: u64,
        owner: Arc<ConnectionOwner>,
    ) -> Result<u64, Value>;
    fn unlisten(&mut self, event: &str, event_id: u64) -> Result<(), Value>;
}

#[derive(Clone, Default)]
pub(crate) struct EventPublisher {
    inner: Arc<Mutex<PublisherState>>,
}
#[derive(Default)]
struct PublisherState {
    next_session: u64,
    sessions: HashMap<u64, Weak<Mutex<HashMap<u64, EventSubscription>>>>,
}
#[derive(Clone)]
struct EventSubscription {
    callback_id: u64,
    generation: u64,
    owner: Arc<ConnectionOwner>,
    event: String,
    deliveries: tokio::sync::mpsc::Sender<crate::bridge::ChannelDelivery>,
    next_index: u64,
}

impl EventPublisher {
    pub(crate) fn publish(&self, event: &str, payload: Value) {
        let sessions = {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.sessions.retain(|_, scope| scope.strong_count() > 0);
            state
                .sessions
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        for scope in sessions {
            let mut registrations = scope
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for registration in registrations
                .values_mut()
                .filter(|entry| entry.event == event && entry.owner.is_active())
            {
                let delivery = crate::bridge::ChannelDelivery {
                    id: registration.callback_id,
                    index: registration.next_index,
                    message: serde_json::json!({
                        "event": registration.event,
                        "id": registration.callback_id,
                        "payload": payload,
                    }),
                    raw: None,
                    generation: registration.generation,
                    owner_id: registration.owner.id(),
                };
                registration.next_index = registration.next_index.saturating_add(1);
                if !registration.owner.is_active() {
                    continue;
                }
                if let Err(error) = registration.deliveries.try_send(delivery) {
                    eprintln!(
                        "bridge event delivery queue unavailable for {}: {error}",
                        registration.event
                    );
                    registration.owner.overload();
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn subscription_count(&self) -> usize {
        let sessions = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .values()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        sessions
            .iter()
            .map(|scope| {
                scope
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }

    fn session(
        &self,
        deliveries: tokio::sync::mpsc::Sender<crate::bridge::ChannelDelivery>,
    ) -> PublisherSession {
        let registrations = Arc::new(Mutex::new(HashMap::new()));
        let id = {
            let mut state = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let id = state.next_session;
            state.next_session = state.next_session.saturating_add(1);
            state.sessions.insert(id, Arc::downgrade(&registrations));
            id
        };
        PublisherSession {
            publisher: self.clone(),
            id,
            registrations,
            deliveries,
            used_callbacks: std::collections::HashSet::new(),
        }
    }
}

struct PublisherSession {
    publisher: EventPublisher,
    id: u64,
    registrations: Arc<Mutex<HashMap<u64, EventSubscription>>>,
    deliveries: tokio::sync::mpsc::Sender<crate::bridge::ChannelDelivery>,
    used_callbacks: std::collections::HashSet<u64>,
}
impl Drop for PublisherSession {
    fn drop(&mut self) {
        self.publisher
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .remove(&self.id);
        self.registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}
impl SessionSubscriptions for PublisherSession {
    fn listen(
        &mut self,
        event: &str,
        target: &Value,
        handler: u64,
        generation: u64,
        owner: Arc<ConnectionOwner>,
    ) -> Result<u64, Value> {
        if event.is_empty()
            || !event.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'/' | b':' | b'_')
            })
        {
            return Err(Value::String("invalid event name".into()));
        }
        if !crate::bridge::is_callback_id(handler) {
            return Err(Value::String(
                "event handler callback id outside callback namespace".into(),
            ));
        }
        // Supported shim targets: app-wide Any, or the daemon's current
        // main webview/window labels used by current-view listeners. This is
        // not the full desktop EventTarget matcher (arbitrary labels and
        // window lifecycle semantics are intentionally unsupported).
        let current_label = ["AnyLabel", "Window", "Webview", "WebviewWindow"]
            .iter()
            .any(|kind| target == &serde_json::json!({"kind":kind,"label":"main"}));
        let supported = target == &serde_json::json!({"kind":"Any"})
            || target == &serde_json::json!({"kind":"App"})
            || current_label;
        if !supported {
            return Err(Value::String("unsupported event target".into()));
        }
        if !self.used_callbacks.insert(handler) {
            return Err(Value::String(
                "event callback id was already used on this connection".into(),
            ));
        }
        let mut registrations = self
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registrations.contains_key(&handler) {
            return Err(Value::String("event callback already registered".into()));
        }
        registrations.insert(
            handler,
            EventSubscription {
                callback_id: handler,
                generation,
                owner,
                event: event.to_owned(),
                deliveries: self.deliveries.clone(),
                next_index: 0,
            },
        );
        Ok(handler)
    }
    fn unlisten(&mut self, event: &str, event_id: u64) -> Result<(), Value> {
        let mut registrations = self
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if registrations
            .get(&event_id)
            .is_some_and(|entry| entry.event == event)
        {
            registrations.remove(&event_id);
        }
        Ok(())
    }
}

fn required_string(body: &Value, key: &str) -> Result<String, Value> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Value::String(format!("missing string argument: {key}")))
}

pub(crate) struct HostAdapter<R: Runtime> {
    app: AppHandle<R>,
    publisher: EventPublisher,
}

impl<R: Runtime> HostAdapter<R> {
    #[cfg(test)]
    pub(crate) fn new(app: AppHandle<R>) -> Self {
        Self {
            app,
            publisher: EventPublisher::default(),
        }
    }

    pub(crate) fn with_publisher(app: AppHandle<R>, publisher: EventPublisher) -> Self {
        Self { app, publisher }
    }
}

impl<R: Runtime> InvocationAdapter for HostAdapter<R> {
    fn create_subscriptions(
        &self,
        deliveries: tokio::sync::mpsc::Sender<crate::bridge::ChannelDelivery>,
    ) -> Box<dyn SessionSubscriptions> {
        Box::new(self.publisher.session(deliveries))
    }

    fn invoke(
        &self,
        command: String,
        input: CommandInput,
        context: SessionContext,
        callback_id: u64,
        deliveries: tokio::sync::mpsc::Sender<crate::bridge::ChannelDelivery>,
        owner: Arc<ConnectionOwner>,
    ) -> BoxFuture<'static, Result<AdapterResponse, Value>> {
        let app = self.app.clone();
        Box::pin(async move {
            let CommandInput {
                body,
                raw_body,
                headers,
            } = input;
            // Keep session context explicit at this boundary. WI-11 will validate
            // the bearer; the numeric generation remains opaque and connection-scoped.
            let session_generation = context.generation;
            let _session_token = context.token;
            match command.as_str() {
                "plugin:event|listen" | "plugin:event|unlisten" => {
                    // Subscription controls are interpreted by the bridge session, which owns
                    // the connection-scoped registry; reaching this arm is a routing error.
                    Err(Value::String(
                        "event subscription control requires bridge session".into(),
                    ))
                }
                "pairing_status" => {
                    let id = body
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Value::String("missing string argument: id".into()))?
                        .to_owned();
                    let state = app.state::<Pairing>();
                    crate::pairing::pairing_status(state, id)
                        .map(|result| {
                            AdapterResponse::Json(
                                serde_json::to_value(result).expect("Pairing status serializes"),
                            )
                        })
                        .map_err(Value::String)
                }
                "identity_legacy_available" => {
                    let result = crate::identity::identity_legacy_available(app.clone());
                    Ok(AdapterResponse::Json(Value::Bool(result)))
                }
                "plugin_host_mcp_serve" => {
                    let id = required_string(&body, "id")?;
                    let revision = required_string(&body, "revision")?;
                    let shared_session = body.get("sharedSession").and_then(Value::as_bool);
                    let event_index = std::sync::Arc::new(std::sync::Mutex::new(0u64));
                    let sink = deliveries.clone();
                    let channel_owner = owner.clone();
                    let channel =
                        tauri::ipc::Channel::new(move |message: tauri::ipc::InvokeResponseBody| {
                            let mut next_index = event_index
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let index = *next_index;
                            *next_index = next_index.saturating_add(1);
                            let (message, raw) = match message {
                                tauri::ipc::InvokeResponseBody::Json(json) => (
                                    serde_json::from_str(&json).map_err(tauri::Error::from)?,
                                    None,
                                ),
                                tauri::ipc::InvokeResponseBody::Raw(bytes) => {
                                    (Value::Null, Some(bytes))
                                }
                            };
                            if !channel_owner.is_active() {
                                return Err(tauri::Error::from(std::io::Error::other(
                                    "bridge session was superseded",
                                )));
                            }
                            sink.try_send(crate::bridge::ChannelDelivery {
                                id: callback_id,
                                index,
                                message,
                                raw,
                                generation: session_generation,
                                owner_id: channel_owner.id(),
                            })
                            .map_err(|error| {
                                channel_owner.overload();
                                tauri::Error::from(std::io::Error::other(format!(
                                    "bridge channel delivery queue unavailable: {error}"
                                )))
                            })
                        });
                    let manager = app.state::<crate::PluginManager>();
                    let servers = app.state::<crate::host_mcp::HostMcpServers>();
                    crate::host_mcp::plugin_host_mcp_serve(
                        manager,
                        servers,
                        id,
                        revision,
                        channel,
                        shared_session,
                    )
                    .await
                    .map(|info| {
                        AdapterResponse::Json(
                            serde_json::to_value(info).expect("MCP server info serializes"),
                        )
                    })
                    .map_err(Value::String)
                }
                "plugin_host_resolve_directory" => {
                    let id = required_string(&body, "id")?;
                    let revision = required_string(&body, "revision")?;
                    let path = required_string(&body, "path")?;
                    let create = body.get("create").and_then(Value::as_bool);
                    let manager = app.state::<crate::PluginManager>();
                    crate::host_files::plugin_host_resolve_directory(
                        manager, id, revision, path, create,
                    )
                    .await
                    .map(|path| AdapterResponse::Json(Value::String(path)))
                    .map_err(Value::String)
                }
                "relay_upload_chunk" => {
                    let headers = headers.unwrap_or_default();
                    let header = |name: &str| headers.get(name).and_then(Value::as_str);
                    let bytes = raw_body
                        .ok_or_else(|| Value::String("Upload body must be raw bytes".into()))?;
                    crate::relay::relay_upload_chunk_service(
                        app.clone(),
                        header("x-buzz-upload-id"),
                        header("x-buzz-upload-offset"),
                        Some(&bytes),
                    )
                    .await
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "plugin_host_read_file" => {
                    let id = required_string(&body, "id")?;
                    let revision = required_string(&body, "revision")?;
                    let path = required_string(&body, "path")?;
                    let cwd = body.get("cwd").and_then(Value::as_str).map(str::to_owned);
                    crate::host_files::plugin_host_read_file_service(
                        app.state::<crate::PluginManager>(),
                        id,
                        revision,
                        path,
                        cwd,
                    )
                    .await
                    .map(AdapterResponse::Raw)
                    .map_err(Value::String)
                }
                _ => Err(Value::String(format!("unknown bridge command: {command}"))),
            }
        })
    }
}
