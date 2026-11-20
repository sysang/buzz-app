import { isTauri } from "@tauri-apps/api/core";

// This is deliberately imported immediately after the daemon bootstrap in the
// frontend entry graph. It is a runtime witness that API module evaluation sees
// the injected globals before the rest of the app's dependency graph evaluates.
export const firstFrontendTauriCapture = isTauri();
if (typeof window !== "undefined") {
  Object.defineProperty(window, "__BUZZ_STARTUP_TAURI_CAPTURE__", {
    configurable: false,
    value: firstFrontendTauriCapture,
  });
}
