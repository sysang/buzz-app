import type { daemonEnvironment } from "./environment";

declare global {
  interface Window {
    __TAURI_INTERNALS__?: {
      invoke: (command: string, args?: unknown, options?: { headers?: HeadersInit }) => Promise<unknown>;
      transformCallback: (callback: (...args: unknown[]) => void, once?: boolean) => number;
      runCallback: (id: number, ...args: unknown[]) => void;
      unregisterCallback: (id: number) => void;
      callbacks: Record<number, (...args: unknown[]) => void>;
      metadata: Record<string, unknown>;
      convertFileSrc: (path: string, protocol?: string) => string;
    };
    __TAURI_EVENT_PLUGIN_INTERNALS__?: {
      registerListener: (event: string, eventId: number) => void;
      unregisterListener: (event: string, eventId: number) => void;
    };
    __BUZZ_STARTUP_TAURI_CAPTURE__?: boolean;
    __BUZZ_DAEMON_ENVIRONMENT__?: typeof daemonEnvironment;

  }
  var isTauri: boolean | undefined;
  var __BUZZ_DAEMON_ENVIRONMENT__: typeof daemonEnvironment | undefined;
}

export {};
