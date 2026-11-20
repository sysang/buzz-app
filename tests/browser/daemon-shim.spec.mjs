import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";

const daemonUrl = process.env.BUZZ_DAEMON_URL;
const pinnedApiRoot = new URL("../../node_modules/.pnpm/@tauri-apps+api@2.12.4/node_modules/@tauri-apps/api/", import.meta.url);

async function exposePinnedApi(page) {
  // Serve the exact installed ESM package files into the daemon page origin so
  // the browser executes the real 2.12.4 implementation against the shim.
  await page.route("**/__pinned_tauri_api__/**", async (route) => {
    const url = new URL(route.request().url());
    const relative = decodeURIComponent(url.pathname.split("/__pinned_tauri_api__/")[1] ?? "");
    if (!relative || relative.split("/").includes("..")) return route.abort();
    try {
      const body = await readFile(new URL(relative, pinnedApiRoot));
      await route.fulfill({ status: 200, contentType: "text/javascript; charset=utf-8", body });
    } catch {
      await route.abort();
    }
  });
}

async function gateBridgeOpen(page, tokenOverride) {
  await page.addInitScript((override) => {
    if (override) document.addEventListener("readystatechange", () => {
      const token = document.querySelector('meta[name="buzz-web-token"]');
      if (token) token.content = override;
    }, { once: true });
    const NativeWebSocket = window.WebSocket;
    const nativeReadyState = Object.getOwnPropertyDescriptor(NativeWebSocket.prototype, "readyState").get;
    window.WebSocket = new Proxy(NativeWebSocket, {
      construct(Target, args) {
        const socket = Reflect.construct(Target, args, Target);
        if (String(args[0]).endsWith("/bridge")) {
          let gated = true;
          let openHandler;
          const sent = [];
          const send = socket.send.bind(socket);
          socket.send = (data) => { sent.push(data); send(data); };
          Object.defineProperty(socket, "readyState", { get: () => gated && nativeReadyState.call(socket) === NativeWebSocket.OPEN ? NativeWebSocket.CONNECTING : nativeReadyState.call(socket) });
          Object.defineProperty(socket, "onopen", { configurable: true, get: () => openHandler, set: (value) => { openHandler = value; } });
          socket.addEventListener("open", (event) => { if (!gated) openHandler?.call(socket, event); });
          window.__BUZZ_BRIDGE_SENT__ = sent;
          window.__BUZZ_RELEASE_BRIDGE__ = () => {
            gated = false;
            if (nativeReadyState.call(socket) === NativeWebSocket.OPEN) openHandler?.call(socket, new Event("open"));
          };
        }
        return socket;
      },
    });
  }, tokenOverride);
}

async function openDaemon(page) {
  test.skip(!daemonUrl, "set BUZZ_DAEMON_URL to a running daemon-served page");
  await page.goto(daemonUrl, { waitUntil: "domcontentloaded" });
  await expect.poll(() => page.evaluate(() => window.__BUZZ_STARTUP_TAURI_CAPTURE__)).toBe(true);
}

test("daemon bootstrap is active before the frontend entry captures isTauri", async ({ page }) => {
  await openDaemon(page);
  const state = await page.evaluate(() => ({
    tauri: window.isTauri,
    invoke: typeof window.__TAURI_INTERNALS__?.invoke,
    transformCallback: typeof window.__TAURI_INTERNALS__?.transformCallback,
    runCallback: typeof window.__TAURI_INTERNALS__?.runCallback,
    unregisterCallback: typeof window.__TAURI_INTERNALS__?.unregisterCallback,
    callbacks: typeof window.__TAURI_INTERNALS__?.callbacks,
    metadata: typeof window.__TAURI_INTERNALS__?.metadata,
    convertFileSrc: typeof window.__TAURI_INTERNALS__?.convertFileSrc,
    eventRegister: typeof window.__TAURI_EVENT_PLUGIN_INTERNALS__?.registerListener,
    eventUnregister: typeof window.__TAURI_EVENT_PLUGIN_INTERNALS__?.unregisterListener,
    hostServices: window.__BUZZ_DAEMON_ENVIRONMENT__?.hostServicesAvailable,
    nativeWindow: window.__BUZZ_DAEMON_ENVIRONMENT__?.localNativeWindowAvailable,
    token: Boolean(document.querySelector('meta[name="buzz-web-token"]')?.content),
  }));
  expect(state).toEqual({
    tauri: true, invoke: "function", transformCallback: "function", runCallback: "function",
    unregisterCallback: "function", callbacks: "object", metadata: "object", convertFileSrc: "function",
    eventRegister: "function", eventUnregister: "function", hostServices: true, nativeWindow: false, token: true,
  });
});

test("real pinned API exercises callback allocation and invoke against live shim", async ({ page }) => {
  await exposePinnedApi(page);
  await gateBridgeOpen(page);
  await openDaemon(page);
  const result = await page.evaluate(async () => {
    const api = await import("/__pinned_tauri_api__/core.js");
    const callback = () => undefined;
    const first = api.transformCallback(callback);
    const second = api.transformCallback(callback);
    const invokePending = api.invoke("identity_legacy_available");
    window.__BUZZ_RELEASE_BRIDGE__();
    const invokeResult = await invokePending;
    const invokeIds = window.__BUZZ_BRIDGE_SENT__
      .filter((frame) => typeof frame === "string")
      .map((frame) => JSON.parse(frame))
      .filter((frame) => frame.type === "invoke")
      .map((frame) => frame.id);
    const internals = window.__TAURI_INTERNALS__;
    const called = [];
    internals.callbacks[first]();
    internals.unregisterCallback(first);
    internals.runCallback(second, "callback-arg");
    return {
      first, second, invokeResult, invokeIds,
      callbackKeys: Object.keys(internals.callbacks).map(Number),
      callbackEntry: typeof internals.callbacks[second],
      convertFileSrc: internals.convertFileSrc("/tmp/test-file", "file"),
    };
  });
  expect(result.first).toBeGreaterThanOrEqual(2 ** 52);
  expect(result.first).toBeLessThan(2 ** 53);
  expect(result.second).toBeLessThan(result.first);
  expect(result.second).toBeGreaterThanOrEqual(2 ** 52);
  expect(result.invokeResult).toEqual(expect.any(Boolean));
  expect(result.invokeIds.length).toBeGreaterThan(0);
  expect(result.invokeIds.every((id) => Number.isSafeInteger(id) && id >= 0 && id < 2 ** 52)).toBe(true);
  expect(result.invokeIds.every((id, index, ids) => index === 0 || id > ids[index - 1])).toBe(true);
  expect(result.callbackKeys).toContain(result.second);
  expect(result.callbackEntry).toBe("function");
  // WI-18 owns file URL retargeting; this is the current deterministic passthrough.
  expect(result.convertFileSrc).toBe("/tmp/test-file");
});

test("audited safe command subset preserves JSON response shapes", async ({ page }) => {
  await openDaemon(page);
  const result = await page.evaluate(async () => {
    const invoke = window.__TAURI_INTERNALS__.invoke;
    const resolved = async (command, args = {}) => {
      try { return { ok: true, value: await invoke(command, args) }; }
      catch (error) { return { ok: false, error: String(error) }; }
    };
    return {
      identityAvailable: await resolved("identity_legacy_available"),
      identityRestore: await resolved("identity_restore"),
      agents: await resolved("app_agent_list"),
      agentState: await resolved("app_agent_state_load", { key: "conformance:wi15:absent" }),
      plugins: await resolved("plugin_catalog"),
      legacyCommunities: await resolved("legacy_communities"),
    };
  });
  expect(result.identityAvailable.ok).toBe(true);
  expect(typeof result.identityAvailable.value).toBe("boolean");
  expect(result.identityRestore.ok).toBe(true);
  expect(result.identityRestore.value === null || typeof result.identityRestore.value === "string").toBe(true);
  expect(result.agents.ok).toBe(true);
  expect(Array.isArray(result.agents.value)).toBe(true);
  expect(result.agentState.ok).toBe(true);
  expect(result.agentState.value === null || typeof result.agentState.value === "object").toBe(true);
  expect(result.plugins.ok).toBe(true);
  expect(result.plugins.value).toEqual(expect.objectContaining({
    catalog: expect.objectContaining({ plugins: expect.any(Array) }),
    status: "ready",
  }));
  expect(result.legacyCommunities.ok).toBe(true);
  expect(Array.isArray(result.legacyCommunities.value)).toBe(true);
  // app_agent_state_load and relay_agent_library need an existing agent/community
  // identifier; their Rust bridge tests cover typed payload/error parity without
  // imposing live walkthrough state on this deterministic browser suite.
});

test("event-plugin internals register and unregister through real bridge listener commands", async ({ page }) => {
  await exposePinnedApi(page);
  await openDaemon(page);
  const result = await page.evaluate(async () => {
    const api = await import("/__pinned_tauri_api__/event.js");
    const eventName = "conformance/wi15-round-trip";
    let received;
    const before = new Set(Object.keys(window.__TAURI_INTERNALS__.callbacks));
    const unlisten = await api.listen(eventName, (payload) => { received = payload; });
    const callbackId = Number(Object.keys(window.__TAURI_INTERNALS__.callbacks).find((id) => !before.has(id)));
    const registered = Number.isSafeInteger(callbackId) && callbackId >= 2 ** 52 && callbackId < 2 ** 53;
    await unlisten();
    return { registered, removed: window.__TAURI_INTERNALS__.callbacks[callbackId] === undefined, received };
  });
  expect(result.registered).toBe(true);
  expect(result.removed).toBe(true);
  expect(result.received).toBeUndefined();
});

test("channel marker uses client callback namespace; window-only commands are refused without crashing", async ({ page }) => {
  await exposePinnedApi(page);
  await gateBridgeOpen(page);
  await openDaemon(page);
  const result = await page.evaluate(async () => {
    const api = await import("/__pinned_tauri_api__/core.js");
    const sent = window.__BUZZ_BRIDGE_SENT__;
    const markerId = api.transformCallback(() => undefined);
    // Exercise real @tauri-apps/api serialization while the bridge is gated;
    // a Channel argument encodes to the client marker without dispatching a command.
    const channel = new api.Channel(() => undefined);
    const pending = api.invoke("conformance_channel_marker_only", { onEvent: channel });
    const marked = JSON.stringify(channel);
    const envelope = { index: 0, message: { check: true } };
    let delivered;
    window.__TAURI_INTERNALS__.callbacks[markerId] = (value) => { delivered = value; };
    window.__TAURI_INTERNALS__.runCallback(markerId, envelope);
    const invokeBeforeRelease = sent.length;
    window.__BUZZ_RELEASE_BRIDGE__();
    const outcome = await pending.then(() => "resolved", () => "rejected");
    const refusals = await Promise.all(["window_start_dragging", "title_bar_double_click"].map((command) =>
      window.__TAURI_INTERNALS__.invoke(command).then(
        () => ({ command, rejected: false }),
        (error) => ({ command, rejected: true, error: String(error) }),
      ),
    ));
    return { marked, invokeBeforeRelease, outcome, envelope: delivered, refusals };
  });
  expect(result.marked).toContain("__CHANNEL__:");
  const marker = Number(result.marked.match(/__CHANNEL__:(\d+)/)?.[1]);
  expect(marker).toBeGreaterThanOrEqual(2 ** 52);
  expect(marker).toBeLessThan(2 ** 53);
  expect(result.invokeBeforeRelease).toBe(0);
  expect(result.envelope).toEqual({ index: 0, message: { check: true } });
  // The Rust adapter owns known host commands; unknown/window-only operations
  // are an invoke rejection rather than a renderer crash. Actual client-id
  // channel delivery is covered by the Rust MCP round-trip/parser tests and the
  // live relay channel assertion is an explicit WI-16 gate.
  expect(result.refusals).toHaveLength(2);
  for (const refusal of result.refusals) {
    expect(refusal.rejected).toBe(true);
    expect(refusal.error.toLowerCase()).toContain("unknown");
  }
  expect(result.outcome).toBe("rejected");
});

test("early invokes wait for auth then flush to the real daemon listener", async ({ page }) => {
  await gateBridgeOpen(page);
  await page.goto(daemonUrl, { waitUntil: "domcontentloaded" });
  const before = await page.evaluate(() => {
    window.__BUZZ_EARLY_INVOKE__ = window.__TAURI_INTERNALS__.invoke("identity_legacy_available");
    return window.__BUZZ_BRIDGE_SENT__;
  });
  expect(before).toEqual([]);
  await page.evaluate(() => window.__BUZZ_RELEASE_BRIDGE__());
  await expect.poll(() => page.evaluate(() => window.__BUZZ_BRIDGE_SENT__.length)).toBeGreaterThanOrEqual(2);
  const sent = await page.evaluate(() => window.__BUZZ_BRIDGE_SENT__.map((frame) => JSON.parse(frame)));
  expect(sent[0]).toMatchObject({ type: "auth" });
  expect(sent.slice(1)).toContainEqual(expect.objectContaining({ type: "invoke", cmd: "identity_legacy_available" }));
  await expect.poll(() => page.evaluate(async () => typeof await window.__BUZZ_EARLY_INVOKE__)).toBe("boolean");
});

test("invalid daemon bearer rejects queued invokes after the bounded server auth deadline", async ({ page }) => {
  await gateBridgeOpen(page, "deliberately-invalid-token");
  await page.goto(daemonUrl, { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    window.__BUZZ_EARLY_OUTCOME__ = window.__TAURI_INTERNALS__.invoke("identity_legacy_available")
      .then(() => "unexpected-success", (error) => String(error));
  });
  await page.evaluate(() => window.__BUZZ_RELEASE_BRIDGE__());
  await expect.poll(() => page.evaluate(() => window.__BUZZ_EARLY_OUTCOME__)).toContain("authentication failed");
});
