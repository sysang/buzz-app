// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { createNotifications } from "./platform";

afterEach(() => {
  document.head.innerHTML = "";
  Reflect.deleteProperty(globalThis, "isTauri");
});

it("uses browser notifications rather than desktop notifications in daemon mode", async () => {
  vi.stubGlobal("isTauri", true);
  document.head.innerHTML = '<meta name="buzz-web-token" content="daemon-token">';
  const platform = createNotifications();
  expect(platform.label).toBe("Browser notifications");
  expect(platform.systemManaged).toBeUndefined();
  expect(await platform.permission()).toBe("unsupported");
  platform.dispose();
});
