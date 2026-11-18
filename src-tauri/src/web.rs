//! The daemon's loopback-only HTTP server (WDA-S-02.1): it serves the built
//! shared React frontend over the loopback listener, so a browser reached
//! through the SSH tunnel from the interface machine can load the app. The
//! SSH client forwards the tunnel endpoint (same-port forwarding,
//! `ssh -L <port>:127.0.0.1:<port>`) to this listener, which is bound to
//! loopback only like the host's other listeners.
//!
//! WDA-S-02.2/.3 (HTTP slice, WDA-WI-05): the browser-visible origin is
//! exactly `http://localhost:<port>` on the bound port; every route requires
//! that exact `Host` (DNS-rebinding defense) and rejects any `Origin` that
//! is not exactly that origin, while page/asset loads legitimately carrying
//! no `Origin` are admitted. A per-daemon-start bearer token is delivered
//! only in the served entry page, after those checks pass, and is never
//! logged. No local-process exclusion is claimed (`WDA-D07`, Postponed).
//! The WebSocket upgrade/first-frame checks are WDA-WI-11 (after WDA-WI-08),
//! and the bearer-401 HTTP API class lands with the first bearer-protected
//! HTTP route (media metadata routes, WDA-WI-17); this listener has no
//! API routes yet. The connection discipline beyond the shared loopback
//! bounds is WDA-S-02.4 (WDA-WI-06); the served CSP is WDA-S-02.5, delivered
//! as a real `Content-Security-Policy` response header on every response.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{header, Method, Request, Response, StatusCode};
use std::convert::Infallible;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::loopback;

/// A 256-bit token per daemon start.
const TOKEN_BYTES: usize = 32;

/// The entry page is the only place the token is delivered.
const TOKEN_META_OPEN: &str = "<meta name=\"buzz-web-token\" content=\"";
const TOKEN_META_CLOSE: &str = "\">";

/// The served policy (WDA-S-02.5): the desktop app's Tauri CSP
/// (`tauri.conf.json`, unchanged) adapted to the daemon's own origin and
/// delivered as a real browser response header on every response from this
/// listener. Tauri-webview-only sources (`ipc:`, `http://ipc.localhost`,
/// `buzz-media:`, `http://buzz-media.localhost`) are dropped: no browser
/// can load them and the daemon has no such origins — daemon media is
/// served same-origin (`'self'`). `connect-src` explicitly lists the
/// bridge's `ws://localhost:<port>` endpoint. `wss:` (browser-side
/// public-relay admission in `src/features/relay/native-socket.ts`) and
/// `http://127.0.0.1:*` in `media-src` (the 127.0.0.1 media listener the
/// desktop frontend's media elements use until WDA-S-05 retargets them)
/// are retained from the desktop policy — retentions, not additions.
/// `style-src` keeps the desktop's `'unsafe-inline'` (inline `style`
/// attributes need it); `script-src` never admits `unsafe-inline` or
/// `unsafe-eval`: the page's bootstraps are external same-origin files
/// (`dist/index.html`), so no inline-script exception is required.
/// `font-src` allows same-origin `/assets/*.woff2` font files and the
/// `data:font/woff2|woff` faces the built CSS embeds (`dist/assets/*.css`);
/// without it the policy falls back to `default-src 'self'` and the
/// browser blocks those data-URI fonts.
fn served_csp(port: u16) -> String {
    format!(
        "default-src 'self'; script-src 'self' blob: 'wasm-unsafe-eval'; connect-src 'self' ws://localhost:{port} https://api.github.com https://d2z0pbxrxbsiz5.cloudfront.net https://d10hx6rb3fdt3l.cloudfront.net wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; media-src 'self' blob: https://dwwgwmfqqjotj.cloudfront.net http://127.0.0.1:* https://github.com https://user-images.githubusercontent.com https://private-user-images.githubusercontent.com https://github-production-user-asset-6210df.s3.amazonaws.com https://objects.githubusercontent.com; font-src 'self' data:"
    )
}

/// A frontend asset the server can deliver.
pub(crate) struct FrontendAsset {
    pub(crate) bytes: Vec<u8>,
    pub(crate) mime_type: String,
}

/// Percent-decodes and normalizes a request path into an asset key (`index.html`,
/// `assets/main.js`), or `None` when the path is malformed or escapes the
/// frontend root. Tauri's asset resolver does not reject `..` segments itself,
/// so the check belongs here, before any lookup happens.
fn normalized(path: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .ok()?;
    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            segment if segment.contains(['\\', '\0']) => return None,
            segment => segments.push(segment),
        }
    }
    let joined = segments.join("/");
    Some(if joined.is_empty() {
        "index.html".to_owned()
    } else {
        joined
    })
}

fn whole(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// The pinned HTTP policy for the one approved browser-visible origin:
/// `http://localhost:<port>` on the daemon's bound port (same-port SSH
/// forwarding). The bound listener authority `127.0.0.1:<port>` is not a
/// trusted Host or Origin. DNS-rebinding defense: the `Host` must match
/// exactly, so a browser visiting a foreign name pointed at loopback is
/// refused before any route logic runs. `page/assets` loads carry no
/// `Origin` and are admitted; a supplied `Origin` must be exact.
struct Policy {
    /// `localhost:<port>` — the only exact `Host` admitted on any route.
    host: String,
    /// `http://localhost:<port>` — the only exact `Origin` admitted when present.
    origin: String,
    /// The per-start bearer token. Never logged; delivered only in the
    /// served entry page.
    token: Zeroizing<String>,
    /// The served `Content-Security-Policy` for this bound port.
    csp: String,
}

impl Policy {
    fn for_port(port: u16, token: Zeroizing<String>) -> Self {
        Self {
            host: format!("localhost:{port}"),
            origin: format!("http://localhost:{port}"),
            token,
            csp: served_csp(port),
        }
    }

    /// Builds the policy for the bound authority and mints this daemon
    /// start's bearer token. Fails closed: no usable policy, no listener.
    fn for_authority(authority: &str) -> Result<Self, String> {
        let port = authority
            .strip_prefix("127.0.0.1:")
            .and_then(|port| port.parse::<u16>().ok())
            .ok_or_else(|| "Could not start the Buzz web interface".to_string())?;
        let mut secret = Zeroizing::new([0u8; TOKEN_BYTES]);
        getrandom::fill(&mut *secret)
            .map_err(|_| "Could not start the Buzz web interface".to_string())?;
        Ok(Self::for_port(
            port,
            Zeroizing::new(URL_SAFE_NO_PAD.encode(&secret[..])),
        ))
    }

    fn allows_host(&self, host: Option<&str>) -> bool {
        host.is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
    }

    fn allows_origin(&self, origin: Option<&str>) -> bool {
        origin.map_or(true, |origin| origin == self.origin)
    }
}

/// Embeds the per-start bearer in the served entry page and returns the
/// bytes to serve, or `None` when the asset does not carry the marker the
/// embedding relies on (fail closed: no token-less entry page is served).
fn entry_page(html: &[u8], token: &str) -> Option<Vec<u8>> {
    let html = std::str::from_utf8(html).ok()?;
    let marker = html.find("</head>")?;
    let mut body = String::with_capacity(html.len() + TOKEN_META_OPEN.len() + token.len() + 16);
    body.push_str(&html[..marker]);
    body.push_str(TOKEN_META_OPEN);
    body.push_str(token);
    body.push_str(TOKEN_META_CLOSE);
    body.push_str(&html[marker..]);
    Some(body.into_bytes())
}

/// The pure HTTP behavior over an asset lookup: exact Host/Origin policy,
/// method allowlist, path normalization and status/content mapping, with the
/// served CSP (WDA-S-02.5) applied as a response header on every response,
/// including rejections and errors. `lookup` resolves a normalized asset
/// key; the production lookup is Tauri's asset resolver (the embedded assets
/// in release builds, the `dist` directory in development builds).
/// Rejections happen before any lookup happens.
fn respond(
    policy: &Policy,
    lookup: &dyn Fn(&str) -> Option<FrontendAsset>,
    method: &Method,
    path: &str,
    host: Option<&str>,
    origin: Option<&str>,
) -> Response<Full<Bytes>> {
    let mut response = respond_inner(policy, lookup, method, path, host, origin);
    // The policy string is fixed ASCII, so this only fails if the constant
    // is malformed; fail closed on 'none' rather than serve an unprotected
    // or headerless page.
    let value = header::HeaderValue::from_str(&policy.csp)
        .unwrap_or_else(|_| header::HeaderValue::from_static("default-src 'none'"));
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, value);
    response
}

fn respond_inner(
    policy: &Policy,
    lookup: &dyn Fn(&str) -> Option<FrontendAsset>,
    method: &Method,
    path: &str,
    host: Option<&str>,
    origin: Option<&str>,
) -> Response<Full<Bytes>> {
    // DNS-rebinding defense: the exact pinned Host is mandatory on every
    // route, and a supplied Origin must be exact, before anything else.
    if !policy.allows_host(host) || !policy.allows_origin(origin) {
        return whole(
            StatusCode::FORBIDDEN,
            "text/plain",
            Bytes::from("Forbidden"),
        );
    }
    if method != Method::GET && method != Method::HEAD {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .body(Full::new(Bytes::from("Method not allowed")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
    }
    let Some(key) = normalized(path) else {
        return whole(
            StatusCode::BAD_REQUEST,
            "text/plain",
            Bytes::from("Invalid path"),
        );
    };
    match lookup(&key) {
        Some(asset) if key == "index.html" => match entry_page(&asset.bytes, &policy.token) {
            Some(bytes) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, asset.mime_type)
                .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
                // The bearer is per-process and must not be reused from a
                // browser cache after the daemon restarts.
                .header(header::CACHE_CONTROL, "no-store")
                .body(Full::new(Bytes::from(bytes)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            None => whole(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                Bytes::from("Web interface misconfigured"),
            ),
        },
        Some(asset) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, asset.mime_type)
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .body(Full::new(Bytes::from(asset.bytes)))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        None => whole(
            StatusCode::NOT_FOUND,
            "text/plain",
            Bytes::from("Not found"),
        ),
    }
}

/// Return one unambiguous header value. Duplicate or non-ASCII values are
/// represented as an empty (and therefore non-matching) value, never as an
/// absent header; this matters for Origin, where only a genuinely absent
/// header is admitted for page/assets.
fn single_header<'a>(headers: &'a hyper::HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return Some("");
    }
    Some(first.to_str().unwrap_or(""))
}

/// Binds loopback, serves the built frontend, and returns the canonical
/// browser URL the operator uses for the SSH tunnel. Called only in the
/// daemon configuration; the desktop never starts this listener.
pub(crate) fn start(app: &tauri::App<tauri::Wry>) -> Result<String, String> {
    let (listener, authority) =
        loopback::bind().map_err(|_| "Could not start the Buzz web interface".to_string())?;
    // Pin the policy to the bound port and mint this start's bearer token.
    let policy = std::sync::Arc::new(Policy::for_authority(&authority)?);
    let url = format!("http://{}/", policy.host);
    let resolver = std::sync::Arc::new(app.asset_resolver());
    let answer = move |request: Request<Incoming>| {
        let resolver = resolver.clone();
        let policy = policy.clone();
        async move {
            let host = single_header(request.headers(), "host").map(str::to_owned);
            let origin = single_header(request.headers(), "origin").map(str::to_owned);
            let lookup = move |key: &str| {
                resolver.get(key.to_owned()).map(|asset| FrontendAsset {
                    bytes: asset.bytes,
                    mime_type: asset.mime_type,
                })
            };
            Ok::<_, Infallible>(respond(
                &policy,
                &lookup,
                request.method(),
                request.uri().path(),
                host.as_deref(),
                origin.as_deref(),
            ))
        }
    };
    tauri::async_runtime::spawn(loopback::serve(listener, CancellationToken::new(), answer));
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn fixture_lookup(key: &str) -> Option<FrontendAsset> {
        let assets: HashMap<&str, &str> = HashMap::from([
            ("index.html", "text/html"),
            ("assets/main.js", "text/javascript"),
        ]);
        assets.get(key).map(|&mime_type| FrontendAsset {
            bytes: format!(
                "<html><head><title>Buzz</title></head><body>fixture:{key}</body></html>"
            )
            .into_bytes(),
            mime_type: mime_type.to_owned(),
        })
    }

    fn fixture_policy() -> Arc<Policy> {
        Arc::new(Policy::for_port(
            34_489,
            Zeroizing::new("fixture-token".to_string()),
        ))
    }

    const HOST: Option<&str> = Some("localhost:34489");
    const ORIGIN: Option<&str> = Some("http://localhost:34489");

    fn response(method: &str, path: &str) -> Response<Full<Bytes>> {
        respond(
            &fixture_policy(),
            &fixture_lookup,
            &Method::from_bytes(method.as_bytes()).unwrap(),
            path,
            HOST,
            None,
        )
    }

    async fn body(response: Response<Full<Bytes>>) -> String {
        use http_body_util::BodyExt as _;
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn get_root_serves_the_entry_page() {
        let answer = response("GET", "/");
        assert_eq!(answer.status(), StatusCode::OK);
        assert_eq!(answer.headers()[header::CONTENT_TYPE], "text/html");
    }

    #[test]
    fn get_asset_serves_its_bytes_and_type() {
        let answer = response("GET", "/assets/main.js");
        assert_eq!(answer.status(), StatusCode::OK);
        assert_eq!(answer.headers()[header::CONTENT_TYPE], "text/javascript");
    }

    #[test]
    fn missing_asset_is_not_found() {
        let answer = response("GET", "/assets/nope.js");
        assert_eq!(answer.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn traversal_is_rejected_before_lookup() {
        for path in [
            "/../secret",
            "/%2e%2e/secret",
            "/%2e%2e%2fsecret",
            "/assets/../../secret",
            "/%5csecret",
            "/%00secret",
            "/%ff%fe",
        ] {
            assert_eq!(
                response("GET", path).status(),
                StatusCode::BAD_REQUEST,
                "{path}"
            );
        }
    }

    #[test]
    fn other_methods_are_rejected() {
        let answer = response("POST", "/");
        assert_eq!(answer.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(answer.headers()[header::ALLOW], "GET, HEAD");
    }

    #[test]
    fn head_is_allowed_for_asset_requests() {
        // The response builder admits HEAD; this test pins the method
        // allowlist, not hyper's wire framing.
        let answer = response("HEAD", "/");
        assert_eq!(answer.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_host_is_forbidden_for_pages_assets_and_other_methods() {
        for host in [
            None,
            Some(""),
            Some("127.0.0.1:34489"),
            Some("localhost:34490"),
            Some("localhost"),
            Some("evil.com:34489"),
            Some("localhost:34489 "),
            Some("localhost:34489."),
        ] {
            for method_path in [("GET", "/"), ("GET", "/assets/main.js"), ("POST", "/")] {
                let answer = respond(
                    &fixture_policy(),
                    &fixture_lookup,
                    &Method::from_bytes(method_path.0.as_bytes()).unwrap(),
                    method_path.1,
                    host,
                    None,
                );
                assert_eq!(answer.status(), StatusCode::FORBIDDEN, "{host:?}");
                assert!(!body(answer).await.contains("fixture-token"));
            }
        }
    }

    #[tokio::test]
    async fn foreign_origin_is_rejected_even_on_page_and_assets() {
        for origin in [
            "http://evil.example",
            "https://localhost:34489",
            "http://localhost:34490",
            "http://127.0.0.1:34489",
            "http://localhost:34489/path",
            "null",
            "",
        ] {
            for path in ["/", "/assets/main.js"] {
                let answer = respond(
                    &fixture_policy(),
                    &fixture_lookup,
                    &Method::GET,
                    path,
                    HOST,
                    Some(origin),
                );
                assert_eq!(answer.status(), StatusCode::FORBIDDEN, "{origin:?}");
                assert!(!body(answer).await.contains("fixture-token"));
            }
        }
        // An exact Origin on another host's asset is also refused when the
        // Host itself is wrong.
        let answer = respond(
            &fixture_policy(),
            &fixture_lookup,
            &Method::GET,
            "/",
            Some("127.0.0.1:34489"),
            ORIGIN,
        );
        assert_eq!(answer.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn the_exact_origin_is_admitted() {
        for path in ["/", "/assets/main.js"] {
            let answer = respond(
                &fixture_policy(),
                &fixture_lookup,
                &Method::GET,
                path,
                HOST,
                ORIGIN,
            );
            assert_eq!(answer.status(), StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn the_entry_page_delivers_the_token_and_assets_do_not() {
        let entry = response("GET", "/");
        assert_eq!(entry.status(), StatusCode::OK);
        assert_eq!(entry.headers()[header::CACHE_CONTROL], "no-store");
        let entry_body = body(entry).await;
        assert!(
            entry_body.contains("<meta name=\"buzz-web-token\" content=\"fixture-token\">"),
            "{entry_body}"
        );

        let alias = response("GET", "/index.html");
        assert!(body(alias).await.contains("fixture-token"));

        let asset = response("GET", "/assets/main.js");
        assert_eq!(asset.status(), StatusCode::OK);
        assert!(!body(asset).await.contains("fixture-token"));
    }

    #[tokio::test]
    async fn entry_page_without_a_head_marker_fails_closed() {
        let lookup = |key: &str| {
            (key == "index.html").then(|| FrontendAsset {
                bytes: b"<html><body><header>no head marker</header></body></html>".to_vec(),
                mime_type: "text/html".to_owned(),
            })
        };
        let answer = respond(&fixture_policy(), &lookup, &Method::GET, "/", HOST, None);
        assert_eq!(answer.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body(answer).await.contains("fixture-token"));
    }

    const EXPECTED_CSP: &str = "default-src 'self'; script-src 'self' blob: 'wasm-unsafe-eval'; connect-src 'self' ws://localhost:34489 https://api.github.com https://d2z0pbxrxbsiz5.cloudfront.net https://d10hx6rb3fdt3l.cloudfront.net wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; media-src 'self' blob: https://dwwgwmfqqjotj.cloudfront.net http://127.0.0.1:* https://github.com https://user-images.githubusercontent.com https://private-user-images.githubusercontent.com https://github-production-user-asset-6210df.s3.amazonaws.com https://objects.githubusercontent.com; font-src 'self' data:";

    #[test]
    fn every_response_carries_the_served_csp_header() {
        // WDA-S-02.5: the served policy is the desktop CSP adapted to the
        // daemon's origins, delivered as a real response header on success,
        // rejection and error paths alike.
        let entry = response("GET", "/");
        let entry_csp = entry.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .expect("CSP header value must be ASCII")
            .to_owned();
        assert_eq!(entry_csp, EXPECTED_CSP);

        let asset = response("GET", "/assets/main.js");
        assert_eq!(
            asset.headers()[header::CONTENT_SECURITY_POLICY],
            entry_csp,
            "asset response must carry the same policy"
        );

        let missing = response("GET", "/assets/nope.js");
        assert_eq!(
            missing.headers()[header::CONTENT_SECURITY_POLICY],
            entry_csp,
            "404 must carry the policy"
        );

        let denied = respond(
            &fixture_policy(),
            &fixture_lookup,
            &Method::GET,
            "/",
            Some("evil.example:34489"),
            None,
        );
        assert_eq!(
            denied.headers()[header::CONTENT_SECURITY_POLICY],
            entry_csp,
            "403 must carry the policy"
        );

        let method_denied = response("POST", "/");
        assert_eq!(
            method_denied.headers()[header::CONTENT_SECURITY_POLICY],
            entry_csp,
            "405 must carry the policy"
        );

        // The script bootstrap admits only external same-origin (and the
        // desktop's blob:/wasm) sources: never inline, never JS eval.
        // ('wasm-unsafe-eval' is a distinct keyword the desktop policy uses
        // for WebAssembly; it is not 'unsafe-eval'.)
        let script_src = entry_csp
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("script-src"))
            .expect("script-src directive present");
        assert!(!script_src.contains("unsafe-inline"), "{script_src}");
        assert!(!script_src.contains("'unsafe-eval'"), "{script_src}");

        // The bridge endpoint is named exactly, not as a scheme wildcard.
        let connect_src = entry_csp
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("connect-src"))
            .expect("connect-src directive present");
        assert!(
            connect_src.contains("ws://localhost:34489"),
            "{connect_src}"
        );
        assert!(!connect_src.contains("ws://*"), "{connect_src}");
        assert!(!connect_src.contains("wss://*"), "{connect_src}");
    }

    #[test]
    fn host_is_case_insensitive_but_port_and_origin_pins_are_exact() {
        let policy = fixture_policy();
        assert!(policy.allows_host(Some("localhost:34489")));
        assert!(policy.allows_host(Some("LOCALHOST:34489")));
        assert!(!policy.allows_host(Some("localhost:344890")));
        assert!(!policy.allows_host(Some("localhost:034489")));
        assert!(!policy.allows_origin(Some("HTTP://localhost:34489")));
    }

    #[test]
    fn policy_authority_accepts_only_the_bound_loopback_form() {
        assert!(Policy::for_authority("127.0.0.1:34489").is_ok());
        for authority in [
            "0.0.0.0:34489",
            "localhost:34489",
            "127.0.0.2:34489",
            "127.0.0.1:notaport",
            "127.0.0.1:",
            "[::1]:34489",
        ] {
            assert!(Policy::for_authority(authority).is_err(), "{authority}");
        }
    }

    #[tokio::test]
    async fn wire_enforces_host_and_origin_and_delivers_the_token() {
        use std::net::Ipv4Addr;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::TcpStream;

        let (listener, authority) = loopback::bind().expect("bind loopback");
        let port: u16 = authority
            .strip_prefix("127.0.0.1:")
            .unwrap()
            .parse()
            .unwrap();
        let policy = Arc::new(Policy::for_port(
            port,
            Zeroizing::new("wire-fixture-token".to_string()),
        ));
        let stop = CancellationToken::new();
        let answer = move |request: Request<Incoming>| {
            let policy = policy.clone();
            let lookup = fixture_lookup;
            async move {
                let host = single_header(request.headers(), "host").map(str::to_owned);
                let origin = single_header(request.headers(), "origin").map(str::to_owned);
                Ok::<_, Infallible>(respond(
                    &policy,
                    &lookup,
                    request.method(),
                    request.uri().path(),
                    host.as_deref(),
                    origin.as_deref(),
                ))
            }
        };
        let task = tauri::async_runtime::spawn(loopback::serve(listener, stop.clone(), answer));

        async fn raw_http(port: u16, request: String) -> (u16, String) {
            let (status, _head, body) = raw_http_head(port, request.into_bytes()).await;
            (status, body)
        }

        async fn raw_http_bytes(port: u16, request: Vec<u8>) -> (u16, String) {
            let (status, _head, body) = raw_http_head(port, request).await;
            (status, body)
        }

        async fn raw_http_head(port: u16, request: Vec<u8>) -> (u16, String, String) {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .expect("connect");
            stream.write_all(&request).await.expect("write request");
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.expect("read");
            let response = String::from_utf8_lossy(&response).into_owned();
            let (head, body) = response.split_once("\r\n\r\n").expect("head/body");
            let status: u16 = head
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse().ok())
                .expect("status code");
            (status, head.to_string(), body.to_string())
        }

        let request = |path: &str, extra: &str| {
            format!(
                "GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n{extra}Connection: close\r\n\r\n"
            )
        };

        let (status, page) = raw_http(port, request("/", "")).await;
        assert_eq!(status, 200);
        assert!(page.contains("<meta name=\"buzz-web-token\" content=\"wire-fixture-token\">"));

        let (status, asset) = raw_http(port, request("/assets/main.js", "")).await;
        assert_eq!(status, 200);
        assert!(!asset.contains("wire-fixture-token"));

        // HEAD is allowed but must not send the entry body/token on the wire.
        let (status, head_body) = raw_http(
            port,
            format!("HEAD / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 200);
        assert!(
            head_body.is_empty(),
            "HEAD leaked a response body: {head_body}"
        );

        let (status, forbidden) = raw_http(
            port,
            format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 403);
        assert!(!forbidden.contains("wire-fixture-token"));

        let (status, _) = raw_http(
            port,
            format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: http://evil.example\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 403);

        let (status, _) = raw_http(
            port,
            format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: http://localhost:{port}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 200);

        // A malformed or duplicate Origin is supplied, not absent; neither
        // may fall through the page's Origin-optional policy.
        let mut malformed_origin =
            format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: ").into_bytes();
        malformed_origin.push(0xff);
        malformed_origin.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        let (status, body) = raw_http_bytes(port, malformed_origin).await;
        assert_ne!(status, 200);
        assert!(!body.contains("wire-fixture-token"));

        let (status, body) = raw_http(
            port,
            format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: http://localhost:{port}\r\nOrigin: http://evil.example\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 403);
        assert!(!body.contains("wire-fixture-token"));

        let (status, body) = raw_http(
            port,
            format!("GET / HTTP/1.1\r\nHost: localhost:{port}\r\nHost: evil.example:{port}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_ne!(status, 200);
        assert!(!body.contains("wire-fixture-token"));

        // WDA-S-02.5: the served CSP arrives as a real response header on
        // the wire, for the entry page and for assets, and names the
        // daemon's own bridge origin explicitly.
        let (status, head, _) = raw_http_head(port, request("/", "").into_bytes()).await;
        assert_eq!(status, 200);
        let page_csp = head
            .lines()
            .find(|line| {
                line.to_ascii_lowercase()
                    .starts_with("content-security-policy:")
            })
            .expect("entry page must carry a Content-Security-Policy header");
        assert!(page_csp.contains(&format!("ws://localhost:{port}")));
        // The served policy admits the same-origin and data-URI font
        // sources the built CSS uses, so the browser does not block them.
        assert!(page_csp.contains("font-src 'self' data:"));
        let (status, head, _) =
            raw_http_head(port, request("/assets/main.js", "").into_bytes()).await;
        assert_eq!(status, 200);
        let asset_csp = head
            .lines()
            .find(|line| {
                line.to_ascii_lowercase()
                    .starts_with("content-security-policy:")
            })
            .expect("asset response must carry a Content-Security-Policy header");
        assert_eq!(asset_csp, page_csp);

        let (status, _) = raw_http(port, request("/assets/nope.js", "")).await;
        assert_eq!(status, 404);

        let (status, _) = raw_http(
            port,
            format!("POST / HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 405);

        stop.cancel();
        let _ = task.await;
    }
}
