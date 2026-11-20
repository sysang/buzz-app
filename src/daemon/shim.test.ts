import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @vitest-environment jsdom
import { convertFileSrc, invoke, isTauri, transformCallback } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { DaemonBridge } from "./shim";

class Socket {
  static OPEN = 1;
  static CONNECTING = 0;
  readyState = Socket.CONNECTING;
  binaryType = "";
  sent: Array<string | ArrayBuffer> = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((event: { code: number; reason: string }) => void) | null = null;
  send(data: string | ArrayBuffer) { this.sent.push(data); }
  close(code = 1000, reason = "") { this.readyState = 3; this.onclose?.({ code, reason }); }
  open() { this.readyState = Socket.OPEN; this.onopen?.(); }
  receive(data: unknown) { this.onmessage?.({ data }); }
}

const sockets: Socket[] = [];
const bridge = () => new DaemonBridge(() => {
  const socket = new Socket();
  sockets.push(socket);
  return socket as unknown as WebSocket;
});

beforeEach(() => { document.head.innerHTML = '<meta name="buzz-web-token" content="test-token">'; });
afterEach(() => { document.head.innerHTML = ""; sockets.splice(0); vi.restoreAllMocks(); });

describe("daemon injected surface callback semantics", () => {
  it("transforms, runs, unregisters, and supports once callbacks", () => {
    const client = bridge();
    const callback = vi.fn();
    const id = client.transformCallback(callback);
    client.runCallback(id, 1, "two");
    expect(callback).toHaveBeenCalledWith(1, "two");
    client.unregisterCallback(id);
    client.runCallback(id, 3);
    expect(callback).toHaveBeenCalledTimes(1);
    const once = vi.fn();
    const onceId = client.transformCallback(once, true);
    client.runCallback(onceId, "first");
    client.runCallback(onceId, "second");
    expect(once).toHaveBeenCalledTimes(1);
  });

  it("exposes the same exercised globals through the pinned core API", async () => {
    const client = bridge();
    window.__TAURI_INTERNALS__ = {
      invoke: client.invoke.bind(client),
      transformCallback: client.transformCallback.bind(client),
      runCallback: client.runCallback.bind(client),
      unregisterCallback: client.unregisterCallback.bind(client),
      callbacks: client.callbacks,
      metadata: client.metadata,
      convertFileSrc: (path) => path,
    };
    vi.stubGlobal("isTauri", true);
    expect(isTauri()).toBe(true);
    expect(convertFileSrc("/file/path")).toBe("/file/path");
    const callback = vi.fn();
    const callbackId = transformCallback(callback);
    window.__TAURI_INTERNALS__.runCallback(callbackId, "api-call");
    expect(callback).toHaveBeenCalledWith("api-call");

    client.connect();
    const socket = sockets[0]!;
    socket.open();
    const result = invoke("identity_legacy_available");
    socket.receive(JSON.stringify({ type: "invoke_ok", id: 0, payload: true }));
    await expect(result).resolves.toBe(true);
  });

  it("matches the event API listen, receive, and unlisten lifecycle", async () => {
    const client = bridge();
    window.__TAURI_INTERNALS__ = {
      invoke: client.invoke.bind(client),
      transformCallback: client.transformCallback.bind(client),
      runCallback: client.runCallback.bind(client),
      unregisterCallback: client.unregisterCallback.bind(client),
      callbacks: client.callbacks,
      metadata: client.metadata,
      convertFileSrc: (path) => path,
    };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
      unregisterListener: (event, id) => client.unregisterListener(event, id),
    };
    client.connect();
    const socket = sockets[0]!;
    socket.open();
    const received = vi.fn();
    const listening = listen("test-event", received);
    const listenFrame = JSON.parse(socket.sent[1] as string) as { id: number; body: { value: { handler: number } } };
    const callbackId = listenFrame.body.value.handler;
    socket.receive(JSON.stringify({ type: "invoke_ok", id: listenFrame.id, payload: 73 }));
    const unlisten = await listening;
    socket.receive(JSON.stringify({ type: "callback", id: callbackId, envelope: { index: 0, message: { event: "test-event", id: 73, payload: "hello" } } }));
    expect(received).toHaveBeenCalledWith({ event: "test-event", id: 73, payload: "hello" });
    const unlistening = unlisten();
    expect(client.callbacks[callbackId]).toBeUndefined();
    const unlistenFrame = JSON.parse(socket.sent[2] as string) as { id: number };
    socket.receive(JSON.stringify({ type: "invoke_ok", id: unlistenFrame.id, payload: null }));
    await unlistening;
  });

  it("decodes binary invoke responses to ArrayBuffer", async () => {
    const client = bridge();
    client.connect();
    const socket = sockets[0]!;
    socket.open();
    const promise = client.invoke("raw_download");
    const response = new Uint8Array(11);
    response[0] = 1;
    new DataView(response.buffer).setBigUint64(1, 0n, true);
    response.set([0xde, 0xad], 9);
    socket.receive(response.buffer);
    const payload = await promise;
    expect(payload).toBeInstanceOf(ArrayBuffer);
    expect([...new Uint8Array(payload as ArrayBuffer)]).toEqual([0xde, 0xad]);
  });

  it("decodes raw callback envelopes to ArrayBuffer with their envelope index", () => {
    const client = bridge();
    const callback = vi.fn();
    const id = client.transformCallback(callback);
    client.connect();
    const socket = sockets[0]!;
    socket.open();
    socket.receive(JSON.stringify({ type: "callback", id, envelope: { index: 7, message: null } }));
    const frame = new Uint8Array(11);
    frame[0] = 2;
    new DataView(frame.buffer).setBigUint64(1, BigInt(id), true);
    frame.set([0xca, 0xfe], 9);
    socket.receive(frame.buffer);
    expect(callback).toHaveBeenCalledTimes(1);
    const delivered = callback.mock.calls[0]![0] as { index: number; message: ArrayBuffer };
    expect(delivered.index).toBe(7);
    expect(delivered.message).toBeInstanceOf(ArrayBuffer);
    expect([...new Uint8Array(delivered.message)]).toEqual([0xca, 0xfe]);
  });

  it("preserves JSON error values on promise rejection", async () => {
    const client = bridge();
    client.connect();
    const socket = sockets[0]!;
    socket.open();
    const error = { reason: "denied", detail: [1, null] };
    const result = client.invoke("restricted");
    socket.receive(JSON.stringify({ type: "invoke_err", id: 0, error }));
    await expect(result).rejects.toEqual(error);
  });

  it("queues startup invokes and sends auth before flushing them", async () => {
    const client = bridge();
    client.connect();
    const socket = sockets[0]!;
    const result = client.invoke("pairing_status");
    expect(socket.sent).toEqual([]);
    socket.open();
    expect(JSON.parse(socket.sent[0] as string)).toMatchObject({ type: "auth", token: "test-token" });
    expect(JSON.parse(socket.sent[1] as string)).toMatchObject({ type: "invoke", cmd: "pairing_status" });
    socket.receive(JSON.stringify({ type: "invoke_ok", id: 0, payload: { ready: true } }));
    await expect(result).resolves.toEqual({ ready: true });
  });

  it("rejects a queued invoke visibly on authentication failure", async () => {
    document.head.innerHTML = '<meta name="buzz-web-token" content="bad-token">';
    const client = bridge();
    client.connect();
    const socket = sockets[0]!;
    const pending = client.invoke("pairing_status");
    socket.open();
    socket.close(4003, "authentication failed");
    await expect(pending).rejects.toThrow(/authentication failed/);
  });
});
