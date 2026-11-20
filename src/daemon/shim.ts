import { daemonEnvironment } from "./environment";

const MAX_EARLY_INVOKES = 256;
const INVOKE_ID_LIMIT = 2 ** 52;
const AUTH_TIMEOUT_MS = 6_000;
type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type PendingInvoke = {
  resolve(value: unknown): void;
  reject(reason: unknown): void;
  listenerRegistration?: { event: string; callback: number };
};
type Callback = (...args: unknown[]) => void;
type Envelope = { index: number; message?: unknown; end?: true };
type Internals = {
  invoke(command: string, args?: unknown, options?: { headers?: HeadersInit }): Promise<unknown>;
  transformCallback(callback: Callback, once?: boolean): number;
  runCallback(id: number, ...args: unknown[]): void;
  unregisterCallback(id: number): void;
  callbacks: Record<number, Callback>;
  metadata: Record<string, unknown>;
  convertFileSrc(path: string, protocol?: string): string;
};

export class DaemonBridge {
  readonly callbacks: Record<number, Callback> = Object.create(null) as Record<number, Callback>;
  readonly metadata = Object.freeze({ currentWindow: { label: "main" }, currentWebview: { label: "main" } });
  private readonly pending = new Map<number, PendingInvoke>();
  private readonly early: Array<{ frame: string; raw: ArrayBuffer | undefined; pending: PendingInvoke }> = [];
  private readonly listeners = new Map<number, { event: string; callback: number }>();
  private readonly eventCallbacks = new Set<number>();
  private socket: WebSocket | null = null;
  private nextInvokeId = 0;
  // The server allocates callback IDs upward from 2^52; client callbacks grow
  // downward in the same namespace to avoid allocator collisions.
  private nextCallbackId = Number.MAX_SAFE_INTEGER;
  private generation = Date.now() * 1024 + Math.floor(Math.random() * 1024);
  private authTimer: ReturnType<typeof setTimeout> | undefined;
  private failed: Error | undefined;

  constructor(private readonly socketFactory: (url: string) => WebSocket = (url) => new WebSocket(url)) {}

  connect(): void {
    const token = document.querySelector<HTMLMetaElement>('meta[name="buzz-web-token"]')?.content;
    if (!token) throw new Error("Daemon bridge token is missing from the entry page");
    const url = `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/bridge`;
    const socket = this.socketFactory(url);
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    this.authTimer = setTimeout(() => {
      if (socket.readyState !== WebSocket.OPEN) this.fail(new Error("Daemon bridge connection timed out before authentication"));
    }, AUTH_TIMEOUT_MS);
    socket.onopen = () => {
      if (socket !== this.socket) return;
      if (this.authTimer) clearTimeout(this.authTimer);
      socket.send(JSON.stringify({ type: "auth", token, generation: this.generation }));
      // The accepted protocol has no auth-ack frame. WebSocket ordering makes
      // queued invokes follow auth; an invalid bearer closes before dispatch.
      this.flushEarly();
    };
    socket.onmessage = (event) => this.receive(event.data);
    socket.onerror = () => this.fail(new Error("Daemon bridge connection failed"));
    socket.onclose = (event) => this.fail(new Error(`Daemon bridge closed (${event.code || "unknown"}): ${event.reason || "authentication or transport failure"}`));
  }

  invoke(command: string, args: unknown = {}, options?: { headers?: HeadersInit }): Promise<unknown> {
    if (this.failed) return Promise.reject(this.failed);
    if (!Number.isSafeInteger(this.nextInvokeId) || this.nextInvokeId >= INVOKE_ID_LIMIT) {
      return Promise.reject(new Error("Daemon invoke id space exhausted"));
    }
    const id = this.nextInvokeId++;
    const pending = {} as PendingInvoke;
    if (command === "plugin:event|listen" && args && typeof args === "object") {
      const values = args as { event?: unknown; handler?: unknown };
      const handler = typeof values.handler === "number"
        ? values.handler
        : values.handler && typeof values.handler === "object" && "id" in values.handler
          ? (values.handler as { id: number }).id
          : typeof values.handler === "string" && values.handler.startsWith("__CHANNEL__:")
            ? Number(values.handler.slice("__CHANNEL__:".length))
            : undefined;
      if (typeof values.event === "string" && Number.isSafeInteger(handler)) {
        pending.listenerRegistration = { event: values.event, callback: handler as number };
      }
    }
    const promise = new Promise<unknown>((resolve, reject) => Object.assign(pending, { resolve, reject }));
    const raw: ArrayBuffer | undefined = args instanceof ArrayBuffer
      ? args
      : ArrayBuffer.isView(args)
        ? new Uint8Array(args.buffer, args.byteOffset, args.byteLength).slice().buffer as ArrayBuffer
        : undefined;
    const body = raw
      ? { kind: "raw" }
      : { kind: "json", value: this.encode(args) };
    const headers = options?.headers ? Object.fromEntries(new Headers(options.headers).entries()) : undefined;
    const frame = JSON.stringify({ type: "invoke", id, cmd: command, body, ...(headers ? { headers } : {}) });
    this.pending.set(id, pending);
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      if (this.early.length >= MAX_EARLY_INVOKES) {
        this.pending.delete(id);
        pending.reject(new Error(`Daemon bridge startup queue is full (${MAX_EARLY_INVOKES} invokes)`));
        return promise;
      }
      this.early.push({ frame, raw, pending });
    } else {
      this.send(frame, raw);
    }
    return promise;
  }

  transformCallback(callback: Callback, once = false): number {
    if (!Number.isSafeInteger(this.nextCallbackId) || this.nextCallbackId > Number.MAX_SAFE_INTEGER) {
      throw new Error("Daemon callback id space exhausted");
    }
    const id = this.nextCallbackId--;
    this.callbacks[id] = (...args) => {
      if (once) delete this.callbacks[id];
      callback(...args);
    };
    return id;
  }

  runCallback(id: number, ...args: unknown[]): void {
    this.callbacks[id]?.(...args);
  }

  unregisterCallback(id: number): void {
    delete this.callbacks[id];
  }

  registerListener(event: string, eventId: number, callback = eventId): void {
    this.listeners.set(eventId, { event, callback });
    this.eventCallbacks.add(callback);
  }

  unregisterListener(event: string, eventId: number): void {
    const listener = this.listeners.get(eventId);
    if (listener?.event === event) {
      this.listeners.delete(eventId);
      this.eventCallbacks.delete(listener.callback);
      this.unregisterCallback(listener.callback);
    }
  }

  dispose(): void {
    if (this.authTimer) clearTimeout(this.authTimer);
    this.socket?.close(1000, "page disposed");
    this.fail(new Error("Daemon bridge disposed"));
  }

  private flushEarly(): void {
    for (const item of this.early.splice(0)) this.send(item.frame, item.raw);
  }

  private send(frame: string, raw?: ArrayBuffer): void {
    const socket = this.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      this.fail(new Error("Daemon bridge is not connected"));
      return;
    }
    try {
      socket.send(frame);
      if (raw) socket.send(raw);
    } catch (error) {
      this.fail(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private receive(data: unknown): void {
    if (data instanceof ArrayBuffer) {
      const bytes = new Uint8Array(data);
      if (bytes.byteLength < 9) return this.fail(new Error("Malformed daemon binary response"));
      const id = Number(new DataView(data).getBigUint64(1, true));
      const payload = bytes.slice(9).buffer;
      if (bytes[0] === 1) {
        const pending = this.pending.get(id);
        if (pending) { this.pending.delete(id); pending.resolve(payload); }
      } else if (bytes[0] === 2) {
        const envelope = this.rawEnvelope.get(id);
        if (!envelope) return this.fail(new Error("Binary channel frame arrived without its raw envelope"));
        this.rawEnvelope.delete(id);
        this.runCallback(id, { ...envelope, message: payload });
      } else this.fail(new Error("Unknown daemon binary frame tag"));
      return;
    }
    if (typeof data !== "string") return this.fail(new Error("Unexpected daemon WebSocket frame"));
    let frame: Record<string, unknown>;
    try { frame = JSON.parse(data) as Record<string, unknown>; }
    catch { return this.fail(new Error("Malformed daemon JSON frame")); }
    if (frame.type === "invoke_ok" && typeof frame.id === "number") {
      const pending = this.pending.get(frame.id);
      if (pending) {
        this.pending.delete(frame.id);
        if (pending.listenerRegistration && typeof frame.payload === "number") {
          this.registerListener(pending.listenerRegistration.event, frame.payload, pending.listenerRegistration.callback);
        }
        pending.resolve(frame.payload);
      }
    } else if (frame.type === "invoke_err" && typeof frame.id === "number") {
      const pending = this.pending.get(frame.id);
      if (pending) { this.pending.delete(frame.id); pending.reject(frame.error); }
    } else if (frame.type === "callback" && typeof frame.id === "number" && frame.envelope && typeof frame.envelope === "object") {
      const envelope = frame.envelope as Envelope;
      if (envelope.message === null) this.rawEnvelope.set(frame.id, envelope);
      else if (this.eventCallbacks.has(frame.id)) this.runCallback(frame.id, envelope.message);
      else this.runCallback(frame.id, envelope);
      if (envelope.end) this.unregisterCallback(frame.id);
    } else this.fail(new Error("Unknown daemon bridge response frame"));
  }

  private rawEnvelope = new Map<number, Envelope>();
  private encode(value: unknown): Json {
    return JSON.parse(JSON.stringify(value, (_key, item: unknown) => {
      if (item instanceof ArrayBuffer) return Array.from(new Uint8Array(item));
      if (ArrayBuffer.isView(item)) return Array.from(new Uint8Array(item.buffer, item.byteOffset, item.byteLength));
      return item;
    })) as Json;
  }

  private fail(error: Error): void {
    if (this.failed) return;
    this.failed = error;
    if (this.authTimer) clearTimeout(this.authTimer);
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
    for (const item of this.early.splice(0)) item.pending.reject(error);
    console.error(error);
  }
}

export function installDaemonShim(): DaemonBridge | undefined {
  const token = document.querySelector<HTMLMetaElement>('meta[name="buzz-web-token"]');
  if (!token) return undefined;
  const bridge = new DaemonBridge();
  const internals: Internals = {
    invoke: (command, args, options) => bridge.invoke(command, args, options),
    transformCallback: (callback, once) => bridge.transformCallback(callback, once),
    runCallback: (id, ...args) => bridge.runCallback(id, ...args),
    unregisterCallback: (id) => bridge.unregisterCallback(id),
    callbacks: bridge.callbacks,
    metadata: bridge.metadata,
    // WI-18 will retarget files via WDA-S-05.2/D06 scoped media URLs after
    // WI-17 lands that route. Keep this callable and deterministic meanwhile;
    // do not invent a media URL shape or wire contract in Part 1.
    convertFileSrc: (path) => path,
  };
  Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: false, value: internals });
  Object.defineProperty(window, "__TAURI_EVENT_PLUGIN_INTERNALS__", {
    configurable: false,
    value: {
      registerListener: (event: string, id: number) => bridge.registerListener(event, id),
      unregisterListener: (event: string, id: number) => bridge.unregisterListener(event, id),
    },
  });
  Object.defineProperty(globalThis, "isTauri", { configurable: false, value: true });
  Object.defineProperty(globalThis, "__BUZZ_DAEMON_ENVIRONMENT__", { configurable: false, value: daemonEnvironment });
  bridge.connect();
  return bridge;
}
