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

/// Resolve Tauri's serialized Channel marker from an invoke argument. Tauri's
/// client allocates this callback id; `callback_id` is the bridge's server
/// invoke allocation and is retained only for bodies without a channel marker.
fn channel_callback_id(body: &Value, callback_id: u64) -> Result<u64, Value> {
    let Some(marker) = body.get("onEvent") else {
        return Ok(callback_id);
    };
    if marker.is_null() {
        return Ok(callback_id);
    }
    let marker = marker
        .as_str()
        .and_then(|value| value.strip_prefix("__CHANNEL__:"))
        .ok_or_else(|| Value::String("invalid onEvent channel marker".into()))?;
    let id = marker
        .parse::<u64>()
        .map_err(|_| Value::String("invalid onEvent channel id".into()))?;
    if !crate::bridge::is_callback_id(id) {
        return Err(Value::String(
            "onEvent channel id outside callback namespace".into(),
        ));
    }
    Ok(id)
}

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
                "plugin_catalog" => {
                    let manager = app.state::<crate::PluginManager>();
                    let manager = manager.0.clone().map_err(Value::String)?;
                    tauri::async_runtime::spawn_blocking(move || {
                        Ok(match manager.catalog() {
                            Ok(catalog) => crate::ready(&manager, catalog),
                            Err(reason) => crate::InstallationResult::Recovery {
                                reason,
                                can_reset: true,
                            },
                        })
                    })
                    .await
                    .map_err(|error| Value::String(error.to_string()))?
                    .map(|result| {
                        AdapterResponse::Json(
                            serde_json::to_value(result).expect("plugin catalog serializes"),
                        )
                    })
                    .map_err(Value::String)
                }
                "plugin_managed_refresh" => {
                    let manager = app.state::<crate::PluginManager>();
                    if let Ok(manager) = &manager.0 {
                        crate::packaged_plugins::refresh(manager).await;
                    }
                    let manager = manager.0.clone().map_err(Value::String)?;
                    tauri::async_runtime::spawn_blocking(move || {
                        Ok(match manager.catalog() {
                            Ok(catalog) => crate::ready(&manager, catalog),
                            Err(reason) => crate::InstallationResult::Recovery {
                                reason,
                                can_reset: true,
                            },
                        })
                    })
                    .await
                    .map_err(|error| Value::String(error.to_string()))?
                    .map(|result| {
                        AdapterResponse::Json(
                            serde_json::to_value(result).expect("plugin catalog serializes"),
                        )
                    })
                    .map_err(Value::String)
                }
                "plugin_change" => {
                    let action = required_string(&body, "action")?;
                    let id = required_string(&body, "id")?;
                    app.state::<crate::federated_identity::access::Registrations>()
                        .retire(&id);
                    let manager = app.state::<crate::PluginManager>();
                    let manager = manager.0.clone().map_err(Value::String)?;
                    let changed_id = id.clone();
                    let result = tauri::async_runtime::spawn_blocking(move || {
                        manager
                            .change(&action, &changed_id)
                            .map(|catalog| crate::ready(&manager, catalog))
                    })
                    .await
                    .map_err(|error| Value::String(error.to_string()))?;
                    app.state::<crate::federated_identity::access::Registrations>()
                        .retire(&id);
                    result
                        .map(|result| {
                            AdapterResponse::Json(
                                serde_json::to_value(result).expect("plugin change serializes"),
                            )
                        })
                        .map_err(Value::String)
                }
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
                    let channel_id = channel_callback_id(&body, callback_id)?;
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
                                id: channel_id,
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
                "plugin_host_mcp_reply" => {
                    let id = required_string(&body, "id")?;
                    let handle = body
                        .get("handle")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: handle".into()))?;
                    let request = body
                        .get("request")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: request".into()))?;
                    let reply = body.get("body").and_then(Value::as_str).map(str::to_owned);
                    crate::host_mcp::plugin_host_mcp_reply(
                        app.state::<crate::host_mcp::HostMcpServers>(),
                        id,
                        handle,
                        request,
                        reply,
                    )
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "plugin_host_mcp_close" => {
                    let id = required_string(&body, "id")?;
                    let handle = body
                        .get("handle")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: handle".into()))?;
                    crate::host_mcp::plugin_host_mcp_close(
                        app.state::<crate::host_mcp::HostMcpServers>(),
                        id,
                        handle,
                    )
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "plugin_host_process_spawn" => {
                    let id = required_string(&body, "id")?;
                    let revision = required_string(&body, "revision")?;
                    let process_id = required_string(&body, "processId")?;
                    let args = body
                        .get("args")
                        .and_then(Value::as_array)
                        .ok_or_else(|| Value::String("missing array argument: args".into()))?
                        .iter()
                        .map(|arg| {
                            arg.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| Value::String("invalid process argument".into()))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let cwd = body.get("cwd").and_then(Value::as_str).map(str::to_owned);
                    let env = body
                        .get("env")
                        .cloned()
                        .filter(|value| !value.is_null())
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| Value::String("invalid process environment".into()))?;
                    let mcp = body
                        .get("mcp")
                        .cloned()
                        .filter(|value| !value.is_null())
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| Value::String("invalid MCP process connection".into()))?;
                    let protection = body
                        .get("protection")
                        .cloned()
                        .filter(|value| !value.is_null())
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| Value::String("invalid process protection".into()))?;
                    let agent_credential = body.get("agentCredential").and_then(Value::as_bool);
                    let protected_agent = body
                        .get("protectedAgent")
                        .cloned()
                        .filter(|value| !value.is_null())
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| Value::String("invalid protected agent".into()))?;
                    let secrets = body
                        .get("secrets")
                        .cloned()
                        .filter(|value| !value.is_null())
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| Value::String("invalid process secrets".into()))?;
                    let channel_id = channel_callback_id(&body, callback_id)?;
                    let event_index = std::sync::Arc::new(std::sync::Mutex::new(0u64));
                    let sink = deliveries.clone();
                    let channel_owner = owner.clone();
                    let channel =
                        tauri::ipc::Channel::new(move |event: tauri::ipc::InvokeResponseBody| {
                            let index = {
                                let mut next = event_index
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let index = *next;
                                *next = next.saturating_add(1);
                                index
                            };
                            let message = match event {
                                tauri::ipc::InvokeResponseBody::Json(json) => {
                                    serde_json::from_str::<Value>(&json)
                                        .map_err(tauri::Error::from)?
                                }
                                tauri::ipc::InvokeResponseBody::Raw(_) => {
                                    return Err(tauri::Error::from(std::io::Error::other(
                                        "process event channel delivered an unexpected raw payload",
                                    )))
                                }
                            };
                            if !channel_owner.is_active() {
                                return Err(tauri::Error::from(std::io::Error::other(
                                    "bridge session was superseded",
                                )));
                            }
                            sink.try_send(crate::bridge::ChannelDelivery {
                                id: channel_id,
                                index,
                                message,
                                raw: None,
                                generation: session_generation,
                                owner_id: channel_owner.id(),
                            })
                            .map_err(|error| {
                                channel_owner.overload();
                                tauri::Error::from(std::io::Error::other(format!(
                                    "bridge process event queue unavailable: {error}"
                                )))
                            })
                        });
                    crate::host_process::plugin_host_process_spawn(
                        app.clone(),
                        app.state::<crate::PluginManager>(),
                        app.state::<crate::host_process::HostProcesses>(),
                        id,
                        revision,
                        process_id,
                        args,
                        cwd,
                        env,
                        channel,
                        mcp,
                        protection,
                        agent_credential,
                        protected_agent,
                        secrets,
                    )
                    .await
                    .map(|handle| AdapterResponse::Json(serde_json::json!(handle)))
                    .map_err(Value::String)
                }
                "plugin_host_process_write" => {
                    let id = required_string(&body, "id")?;
                    let handle = body
                        .get("handle")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: handle".into()))?;
                    let data = required_string(&body, "data")?;
                    let close = body
                        .get("close")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| Value::String("missing boolean argument: close".into()))?;
                    crate::host_process::plugin_host_process_write(
                        app.state::<crate::host_process::HostProcesses>(),
                        id,
                        handle,
                        data,
                        close,
                    )
                    .await
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "plugin_host_process_kill" => {
                    let id = required_string(&body, "id")?;
                    let handle = body
                        .get("handle")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: handle".into()))?;
                    crate::host_process::plugin_host_process_kill(
                        app.state::<crate::host_process::HostProcesses>(),
                        id,
                        handle,
                    )
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "plugin_host_process_bind_agent" => {
                    let id = required_string(&body, "id")?;
                    let handle = body
                        .get("handle")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: handle".into()))?;
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    crate::host_process::plugin_host_process_bind_agent(
                        app.state::<crate::host_process::HostProcesses>(),
                        app.state::<crate::credential_service::CredentialService>(),
                        id,
                        handle,
                        pubkey,
                        relay,
                    )
                    .await
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "plugin_host_process_tool_credential" => {
                    let id = required_string(&body, "id")?;
                    let handle = body
                        .get("handle")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: handle".into()))?;
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    crate::host_process::plugin_host_process_tool_credential(
                        app.state::<crate::host_process::HostProcesses>(),
                        app.state::<crate::credential_service::CredentialService>(),
                        id,
                        handle,
                        pubkey,
                        relay,
                    )
                    .await
                    .map(|credential| AdapterResponse::Json(serde_json::json!(credential)))
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
                "identity_restore" => {
                    crate::identity::identity_restore(app.state::<crate::identity::IdentityHost>())
                        .await
                        .map(|viewer| {
                            AdapterResponse::Json(
                                serde_json::to_value(viewer).expect("identity result serializes"),
                            )
                        })
                        .map_err(Value::String)
                }
                "identity_create" => crate::identity::identity_create(
                    app.state::<crate::identity::IdentityHost>(),
                    app.state::<crate::nsec_backup::NsecBackupHost>(),
                )
                .await
                .map(|viewer| AdapterResponse::Json(Value::String(viewer)))
                .map_err(Value::String),
                "identity_import" => {
                    let nsec = required_string(&body, "nsec")?;
                    crate::identity::identity_import(
                        app.state::<crate::identity::IdentityHost>(),
                        app.state::<crate::nsec_backup::NsecBackupHost>(),
                        nsec,
                    )
                    .await
                    .map(|viewer| AdapterResponse::Json(Value::String(viewer)))
                    .map_err(Value::String)
                }
                "app_agent_list" => crate::app_agents::app_agent_list(
                    app.state::<crate::app_agents::AppAgentHost>(),
                )
                .await
                .map(|agents| {
                    AdapterResponse::Json(
                        serde_json::to_value(agents).expect("agent list serializes"),
                    )
                })
                .map_err(Value::String),
                "app_agent_claim" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let revision = body.get("revision").and_then(Value::as_u64);
                    crate::app_agents::app_agent_claim(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        revision,
                    )
                    .await
                    .map(|claimed| AdapterResponse::Json(Value::Bool(claimed)))
                    .map_err(Value::String)
                }
                "app_agent_release" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    crate::app_agents::app_agent_release(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                    );
                    Ok(AdapterResponse::Json(Value::Null))
                }
                "app_agent_publish" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let event = serde_json::from_value::<crate::app_agents::AppAgentEvent>(
                        body.get("event")
                            .cloned()
                            .ok_or_else(|| Value::String("missing event argument".into()))?,
                    )
                    .map_err(|_| Value::String("invalid event argument".into()))?;
                    crate::app_agents::app_agent_publish(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        event,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "app_agent_query" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let filters = serde_json::from_value::<Vec<Value>>(
                        body.get("filters")
                            .cloned()
                            .ok_or_else(|| Value::String("missing filters argument".into()))?,
                    )
                    .map_err(|_| Value::String("invalid filters argument".into()))?;
                    crate::app_agents::app_agent_query(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        filters,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "app_agent_set_picture" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let picture = body
                        .get("picture")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    crate::app_agents::app_agent_set_picture(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        picture,
                    )
                    .await
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "app_agent_remember" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let slug = required_string(&body, "slug")?;
                    let memory = body.get("body").and_then(Value::as_str).map(str::to_owned);
                    let after = body
                        .get("after")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| Value::String("missing integer argument: after".into()))?;
                    crate::app_agents::app_agent_remember(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        slug,
                        memory,
                        after,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "app_agent_upload" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let data = required_string(&body, "data")?;
                    let mime = required_string(&body, "mime")?;
                    crate::app_agents::app_agent_upload(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        data,
                        mime,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "app_agent_media" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let url = required_string(&body, "url")?;
                    crate::app_agents::app_agent_media(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        url,
                    )
                    .await
                    .and_then(|media| {
                        serde_json::to_value(media)
                            .map_err(|_| "agent media could not be encoded".to_owned())
                    })
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "app_agent_git_auth" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let owner = required_string(&body, "owner")?;
                    let repo = required_string(&body, "repo")?;
                    crate::app_agents::app_agent_git_auth(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        owner,
                        repo,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "app_agent_search_profiles" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let query = required_string(&body, "query")?;
                    let limit = body
                        .get("limit")
                        .and_then(Value::as_u64)
                        .and_then(|limit| u32::try_from(limit).ok())
                        .ok_or_else(|| Value::String("missing integer argument: limit".into()))?;
                    crate::app_agents::app_agent_search_profiles(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        query,
                        limit,
                    )
                    .await
                    .map(|found| AdapterResponse::Json(found.unwrap_or(Value::Null)))
                    .map_err(Value::String)
                }
                "app_agent_publish_profile" => {
                    let pubkey = required_string(&body, "pubkey")?;
                    let relay = required_string(&body, "relay")?;
                    let force = body.get("force").and_then(Value::as_bool);
                    crate::app_agents::app_agent_publish_profile(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        pubkey,
                        relay,
                        force,
                    )
                    .await
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "app_agent_create" => {
                    let destination = required_string(&body, "destination")?;
                    let owner = required_string(&body, "owner")?;
                    let agent_type = required_string(&body, "agentType")?;
                    let name = required_string(&body, "name")?;
                    crate::app_agents::app_agent_create(
                        app.state::<crate::app_agents::AppAgentHost>(),
                        app.state::<crate::identity::IdentityHost>(),
                        destination,
                        owner,
                        agent_type,
                        name,
                    )
                    .await
                    .map(|agent| {
                        AdapterResponse::Json(
                            serde_json::to_value(agent).expect("agent creation serializes"),
                        )
                    })
                    .map_err(Value::String)
                }
                "app_agent_state_load" => {
                    let key = body.get("key").and_then(Value::as_str).map(str::to_owned);
                    crate::agent_state::app_agent_state_load(
                        app.state::<crate::agent_state::AgentState>(),
                        key,
                    )
                    .await
                    .map(|state| {
                        AdapterResponse::Json(
                            serde_json::to_value(state).expect("agent state serializes"),
                        )
                    })
                    .map_err(Value::String)
                }
                "app_agent_state_set" => {
                    let key = required_string(&body, "key")?;
                    let value = body.get("value").and_then(Value::as_str).map(str::to_owned);
                    let absent = body.get("absent").and_then(Value::as_bool);
                    crate::agent_state::app_agent_state_set(
                        app.state::<crate::agent_state::AgentState>(),
                        key,
                        value,
                        absent,
                    )
                    .await
                    .map(|previous| {
                        AdapterResponse::Json(
                            serde_json::to_value(previous).expect("agent state result serializes"),
                        )
                    })
                    .map_err(Value::String)
                }
                "relay_direct_message" => {
                    let community = required_string(&body, "community")?;
                    let pubkeys = body
                        .get("pubkeys")
                        .and_then(Value::as_array)
                        .ok_or_else(|| Value::String("missing array argument: pubkeys".into()))?
                        .iter()
                        .map(|key| {
                            key.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| Value::String("invalid pubkeys argument".into()))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    crate::relay::relay_direct_message(
                        app.state::<crate::identity::IdentityHost>(),
                        app.state::<crate::federated_identity::FederatedIdentity>(),
                        community,
                        pubkeys,
                    )
                    .await
                    .map(|id| AdapterResponse::Json(Value::String(id)))
                    .map_err(Value::String)
                }
                "relay_sign" => {
                    let community = required_string(&body, "community")?;
                    let event: crate::identity::EventTemplate = serde_json::from_value(
                        body.get("event")
                            .cloned()
                            .ok_or_else(|| Value::String("missing event argument".into()))?,
                    )
                    .map_err(|_| Value::String("invalid event argument".into()))?;
                    crate::relay::relay_sign(
                        app.state::<crate::identity::IdentityHost>(),
                        community,
                        event,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "relay_agent_library" => {
                    let community = required_string(&body, "community")?;
                    crate::relay::relay_agent_library(
                        app.state::<crate::identity::IdentityHost>(),
                        app.state::<crate::app_agents::AppAgentHost>(),
                        community,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "relay_agent_memories_read" => {
                    let community = required_string(&body, "community")?;
                    let agent = required_string(&body, "agent")?;
                    let slug = body.get("slug").and_then(Value::as_str).map(str::to_owned);
                    crate::relay::agent::relay_agent_memories_read_headless(
                        app.state::<crate::identity::IdentityHost>().inner(),
                        app.state::<crate::federated_identity::FederatedIdentity>()
                            .inner(),
                        community,
                        agent,
                        slug,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "relay_channel_sign" => {
                    let community = required_string(&body, "community")?;
                    let route = required_string(&body, "route")?;
                    let event = body
                        .get("event")
                        .cloned()
                        .ok_or_else(|| Value::String("missing event argument".into()))?;
                    crate::relay::relay_channel_sign(
                        app.state::<crate::identity::IdentityHost>(),
                        community,
                        route,
                        event,
                    )
                    .await
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "legacy_communities" => crate::legacy_communities::legacy_communities()
                    .await
                    .map(|saved| {
                        AdapterResponse::Json(
                            serde_json::to_value(saved).expect("legacy communities serialize"),
                        )
                    })
                    .map_err(Value::String),
                "relay_http" => {
                    let community = required_string(&body, "community")?;
                    let path = required_string(&body, "path")?;
                    let method = required_string(&body, "method")?;
                    let request_body = body.get("body").and_then(Value::as_str).map(str::to_owned);
                    let id = body.get("id").and_then(Value::as_str).map(str::to_owned);
                    crate::relay::relay_http(
                        app.state::<crate::identity::IdentityHost>(),
                        app.state::<crate::federated_identity::FederatedIdentity>(),
                        community,
                        path,
                        method,
                        request_body,
                        id,
                    )
                    .await
                    .and_then(|response| {
                        serde_json::to_value(response)
                            .map_err(|_| "relay response could not be encoded".to_owned())
                    })
                    .map(AdapterResponse::Json)
                    .map_err(Value::String)
                }
                "relay_socket_connect" => {
                    let id = required_string(&body, "id")?;
                    let relay = required_string(&body, "relay")?;
                    let channel_id = channel_callback_id(&body, callback_id)?;
                    let event_index = std::sync::Arc::new(std::sync::Mutex::new(0u64));
                    let sink = deliveries.clone();
                    let channel_owner = owner.clone();
                    let channel =
                        tauri::ipc::Channel::new(move |message: tauri::ipc::InvokeResponseBody| {
                            let index = {
                                let mut next = event_index
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                let index = *next;
                                *next = next.saturating_add(1);
                                index
                            };
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
                                id: channel_id,
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
                    crate::federated_identity::socket::relay_socket_connect(
                        app.state::<crate::federated_identity::socket::Sockets>(),
                        app.state::<crate::federated_identity::FederatedIdentity>(),
                        app.state::<crate::identity::IdentityHost>(),
                        id,
                        relay,
                        channel,
                    )
                    .await
                    .map(|mode| {
                        AdapterResponse::Json(
                            serde_json::to_value(mode).expect("socket mode serializes"),
                        )
                    })
                    .map_err(Value::String)
                }
                "relay_socket_start" => {
                    let id = required_string(&body, "id")?;
                    crate::federated_identity::socket::relay_socket_start(
                        app.state::<crate::federated_identity::socket::Sockets>(),
                        id,
                    )
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "relay_socket_send" => {
                    let id = required_string(&body, "id")?;
                    let data = required_string(&body, "data")?;
                    crate::federated_identity::socket::relay_socket_send(
                        app.state::<crate::federated_identity::socket::Sockets>(),
                        id,
                        data,
                    )
                    .map(|()| AdapterResponse::Json(Value::Null))
                    .map_err(Value::String)
                }
                "relay_socket_close" => {
                    let id = required_string(&body, "id")?;
                    crate::federated_identity::socket::relay_socket_close(
                        app.state::<crate::federated_identity::socket::Sockets>(),
                        app.state::<crate::federated_identity::FederatedIdentity>(),
                        id,
                    );
                    Ok(AdapterResponse::Json(Value::Null))
                }
                "relay_verify_signatures" => {
                    let claims: Vec<crate::relay::SignatureClaim> =
                        serde_json::from_value(body.get("claims").cloned().ok_or_else(|| {
                            Value::String("missing array argument: claims".into())
                        })?)
                        .map_err(|_| Value::String("invalid claims argument".into()))?;
                    crate::relay::relay_verify_signatures(claims)
                        .await
                        .map(|valid| {
                            AdapterResponse::Json(
                                serde_json::to_value(valid).expect("signature results serialize"),
                            )
                        })
                        .map_err(Value::String)
                }
                "keep_awake_set" => {
                    let hold = body
                        .get("hold")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| Value::String("missing boolean argument: hold".into()))?;
                    crate::keep_awake::keep_awake_set(
                        app.state::<crate::keep_awake::KeepAwake>(),
                        hold,
                    )
                    .map(|()| AdapterResponse::Json(Value::Null))
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

#[cfg(test)]
mod channel_id_tests {
    use super::channel_callback_id;
    use crate::bridge::{CALLBACK_NAMESPACE_MIN, MAX_WIRE_ID};

    #[test]
    fn client_channel_marker_selects_client_callback_id() {
        let client_id = MAX_WIRE_ID - 17;
        let body = serde_json::json!({"onEvent": format!("__CHANNEL__:{client_id}")});
        assert_eq!(
            channel_callback_id(&body, CALLBACK_NAMESPACE_MIN).unwrap(),
            client_id
        );
    }

    #[test]
    fn invalid_channel_markers_are_rejected_and_absent_channel_falls_back() {
        assert_eq!(
            channel_callback_id(&serde_json::json!({}), CALLBACK_NAMESPACE_MIN).unwrap(),
            CALLBACK_NAMESPACE_MIN
        );
        for marker in [
            "wrong-prefix:4503599627370497",
            "__CHANNEL__:42",
            "__CHANNEL__:9007199254740992",
        ] {
            let body = serde_json::json!({"onEvent": marker});
            assert!(channel_callback_id(&body, CALLBACK_NAMESPACE_MIN).is_err());
        }
    }
}
