//! The loopback HTTP listener the MCP servers and the credential service
//! share: it binds `127.0.0.1` on a port the OS picks and serves each
//! connection one request with hyper. Callers keep their own handling.
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Open connections per listener: an agent may make several calls at once.
const CONNECTIONS: usize = 32;
/// hyper's smallest read buffer, which bounds a request head.
const HEAD_LIMIT: usize = 8192;
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Peeks at `socket` for a `\r\n\r\n`-terminated head without consuming
/// any bytes, within the same bounds as the HTTP head discipline
/// ([`HEAD_LIMIT`] bytes and five seconds). Returns the complete head, or
/// `None` when it cannot be confirmed within those bounds — the caller
/// then closes the connection, as hyper's header timeout would for a
/// plain-HTTP head that never completes. The whole head can be confirmed
/// here up to [`HEAD_LIMIT`] bytes.
async fn peek_head(socket: &tokio::net::TcpStream) -> Option<Vec<u8>> {
    const DELIMITER: &[u8] = b"\r\n\r\n";
    let deadline = tokio::time::Instant::now() + HEAD_TIMEOUT;
    let mut head = Vec::with_capacity(2048);
    let mut buffer = [0u8; HEAD_LIMIT];
    let mut no_growth = 0usize;
    loop {
        let peeked = tokio::time::timeout_at(deadline, socket.peek(&mut buffer))
            .await
            .ok()?
            .ok()?;
        if peeked == 0 {
            // The peer went away.
            return None;
        }
        let take = peeked.min(HEAD_LIMIT);
        if take > head.len() {
            head.extend_from_slice(&buffer[head.len()..take]);
            no_growth = 0;
        } else {
            // No progress on a repeated peek; bound the iterations.
            no_growth += 1;
            if no_growth >= 64 {
                return None;
            }
        }
        if let Some(end) = head
            .windows(DELIMITER.len())
            .position(|window| window == DELIMITER)
        {
            head.truncate(end + DELIMITER.len());
            return Some(head);
        }
        if head.len() >= HEAD_LIMIT {
            return None;
        }
        tokio::time::timeout_at(deadline, socket.readable())
            .await
            .ok()?
            .ok()?;
    }
}

/// The address a request's connection came from, in its extensions.
#[derive(Clone, Copy)]
pub(crate) struct Peer(pub(crate) std::net::SocketAddr);

/// Binds synchronously, so the address is known before anyone connects, and
/// returns the listener with its `127.0.0.1:<port>` authority.
pub(crate) fn bind() -> std::io::Result<(std::net::TcpListener, String)> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let authority = listener.local_addr()?.to_string();
    Ok((listener, authority))
}

/// Serves `listener` with `answer` until `stop` is cancelled, which also ends
/// the connections still open.
pub(crate) async fn serve<A, F>(listener: std::net::TcpListener, stop: CancellationToken, answer: A)
where
    A: Fn(Request<Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    serve_with(listener, stop, answer, None).await;
}

/// Serves `listener` like [`serve`], additionally taking over connections
/// whose head peeks as the bridge WebSocket upgrade (`WDA-S-03.1`): those are
/// handshaken by the bridge before hyper parses anything, so every other
/// request reaches hyper byte-identically. The probe duplicates the HTTP
/// head discipline's bounds exactly ([`HEAD_LIMIT`], five seconds) and
/// closes on violation.
pub(crate) async fn serve_with<A, F>(
    listener: std::net::TcpListener,
    stop: CancellationToken,
    answer: A,
    upgrade: Option<std::sync::Arc<crate::bridge::BridgeUpgrade>>,
) where
    A: Fn(Request<Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send + 'static,
{
    let Ok(listener) = TcpListener::from_std(listener) else {
        return;
    };
    let connections = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            accepted = async {
                let permit = connections.clone().acquire_owned().await.ok()?;
                Some((permit, listener.accept().await))
            } => accepted,
            () = stop.cancelled() => return,
        };
        let Some((permit, accepted)) = accepted else {
            return;
        };
        let Ok((mut socket, peer)) = accepted else {
            drop(permit);
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let (answer, stop) = (answer.clone(), stop.clone());
        let upgrade_for_task = upgrade.clone();
        tauri::async_runtime::spawn(async move {
            let upgrade = upgrade_for_task;
            let guard = Arc::new(std::sync::Mutex::new(Some(permit)));
            if let Some(upgrade) = &upgrade {
                // Non-consuming head peek, exactly the head discipline's
                // bounds ([`HEAD_LIMIT`], five seconds). A head that is not
                // the bridge upgrade is left untouched for hyper to read.
                match peek_head(&socket).await {
                    Some(head) => {
                        if upgrade.is_websocket(&head) {
                            // The head was peeked, not read: consume exactly it;
                            // anything after it stays for the WebSocket.
                            let mut consumed = vec![0u8; head.len()];
                            if tokio::io::AsyncReadExt::read_exact(&mut socket, &mut consumed)
                                .await
                                .is_err()
                                || consumed != head
                            {
                                return;
                            }
                            let Some(permit) = guard
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .take()
                            else {
                                return;
                            };
                            upgrade
                                .take_over(socket, consumed, permit, stop.clone())
                                .await;
                            return;
                        }
                    }
                    None => return,
                }
            }
            // One request per connection. hyper drops a request whose client
            // closes before its answer. No response through this path is a
            // `101` anymore (the pre-hyper probe owns every WebSocket
            // upgrade), so hyper's `Connection: close` discipline applies
            // exactly as it did before the bridge existed.
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEAD_TIMEOUT)
                .max_buf_size(HEAD_LIMIT)
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(socket),
                    service_fn(move |mut request: Request<Incoming>| {
                        request.extensions_mut().insert(Peer(peer));
                        answer(request)
                    }),
                );
            tokio::select! {
                _ = connection => {}
                () = stop.cancelled() => {}
            }
            // An upgraded connection's answer took the permit and moved it
            // into its session; anything left here is the plain-HTTP case.
            drop(
                guard
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take(),
            );
        });
    }
}

#[cfg(test)]
mod tests {
    //! WDA-S-02.4 (WDA-WI-06) gate for the listener slice: the connection
    //! bound is enforced at the accept/admission boundary, not just declared
    //! in `CONNECTIONS`. Under load the listener serves at most `CONNECTIONS`
    //! connections at once; connections beyond the bound wait instead of
    //! spawning handlers, and cancellation ends the listener cleanly.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpStream;

    /// Polls `condition` until it holds or `budget` elapses; bounded so a
    /// regression fails the test instead of hanging the runner.
    async fn wait_for(mut condition: impl FnMut() -> bool, budget: Duration) {
        let start = Instant::now();
        loop {
            if condition() {
                return;
            }
            assert!(
                start.elapsed() < budget,
                "timed out after {budget:?} waiting for the condition"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn connection_admission_stays_bounded_under_load() {
        const EXCESS: usize = 8;
        let (listener, authority) = bind().expect("bind loopback");
        let port: u16 = authority
            .strip_prefix("127.0.0.1:")
            .and_then(|port| port.parse().ok())
            .expect("loopback authority");

        let entered = Arc::new(AtomicUsize::new(0));
        let gate = CancellationToken::new();
        let stop = CancellationToken::new();

        let answer_entered = entered.clone();
        let answer_gate = gate.clone();
        let answer = move |_request: Request<Incoming>| {
            let entered = answer_entered.clone();
            let gate = answer_gate.clone();
            async move {
                entered.fetch_add(1, Ordering::SeqCst);
                // Hold every admitted handler open until the test releases
                // the gate, so no admission can drain while the bound is
                // observed. The gate is test-side; production code is unchanged.
                gate.cancelled().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        };
        let serve_task = tauri::async_runtime::spawn(serve(listener, stop.clone(), answer));

        // More pending connections than the bound, each with a complete head.
        let mut streams = Vec::with_capacity(CONNECTIONS + EXCESS);
        for _ in 0..CONNECTIONS + EXCESS {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("connect loopback");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .expect("write head");
            streams.push(stream);
        }

        // Exactly the bound is admitted; excess connections wait in the
        // listen backlog and no further handler may start. A regression that
        // accepts without a permit never satisfies `entered == CONNECTIONS`
        // once `EXCESS` connections are pending, so `wait_for` fails.
        wait_for(
            || entered.load(Ordering::SeqCst) == CONNECTIONS,
            Duration::from_secs(5),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            entered.load(Ordering::SeqCst),
            CONNECTIONS,
            "listener admitted more than {CONNECTIONS} concurrent connections"
        );

        // Releasing the handlers drains admission permit-by-permit; pending
        // connections are eventually served rather than refused or leaked.
        gate.cancel();
        wait_for(
            || entered.load(Ordering::SeqCst) == CONNECTIONS + EXCESS,
            Duration::from_secs(5),
        )
        .await;

        drop(streams);
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), serve_task)
            .await
            .expect("serve stops on cancellation")
            .expect("serve task finishes");
    }
}
