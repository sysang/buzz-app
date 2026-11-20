/** Runtime distinctions for the daemon-served browser application. `isTauri()`
 * remains true there because host services are available over the bridge; it is
 * not a test for an addressable local native window.
 */
export const daemonEnvironment = Object.freeze({
  hostServicesAvailable: true,
  localNativeWindowAvailable: false,
  browserCapabilities: Object.freeze({
    clipboard: typeof navigator !== "undefined" && !!navigator.clipboard,
    notifications: typeof Notification !== "undefined",
    filePicking: typeof document !== "undefined" && "showOpenFilePicker" in window,
    wakeLock: typeof navigator !== "undefined" && "wakeLock" in navigator,
    focusVisibility: typeof document !== "undefined",
  }),
});

export function isDaemonMode(): boolean {
  return typeof document !== "undefined" &&
    document.querySelector('meta[name="buzz-web-token"]') !== null;
}

export function hasLocalNativeWindow(hostServicesAvailable = !!(globalThis as { isTauri?: boolean }).isTauri): boolean {
  return hostServicesAvailable && !isDaemonMode();
}
