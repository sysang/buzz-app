// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { daemonEnvironment, hasLocalNativeWindow, isDaemonMode } from "./environment";

afterEach(() => {
  document.head.innerHTML = "";
  Reflect.deleteProperty(globalThis, "isTauri");
});

it("separates daemon host services from local native window capability", () => {
  vi.stubGlobal("isTauri", true);
  expect(daemonEnvironment.hostServicesAvailable).toBe(true);
  expect(daemonEnvironment.localNativeWindowAvailable).toBe(false);
  expect(isDaemonMode()).toBe(false);
  expect(hasLocalNativeWindow()).toBe(true);
  document.head.innerHTML = '<meta name="buzz-web-token" content="daemon-token">';
  expect(isDaemonMode()).toBe(true);
  expect(hasLocalNativeWindow()).toBe(false);
});
