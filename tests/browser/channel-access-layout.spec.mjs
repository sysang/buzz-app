import { test, expect } from "./fixture.mjs";
import { openPage } from "./navigation.mjs";
import { animationsSettled } from "./animations.mjs";
import { openChannelDetails } from "./channel-details.mjs";

test.use({
  productionBroker: true,
  channelLifecycle: true,
  lifecycleRole: "owner",
  sessionMembers: {
    "11111111-1111-4111-8111-111111111111": ["a".repeat(64)],
  },
  historyCounts: { alpha: 1, beta: 1 },
});

// Browser-only: text reflow and clipping need the real panel, dialog and CSS
// layout engine. Role/recovery matrices stay in component/session tests.
test("general access lives in Channel settings and member actions stay reachable with enlarged text", async ({
  page,
  app,
}, testInfo) => {
  // Read a signed View only policy without publishing a metadata change.
  await page.route("**/query", async (route) => {
    const response = await route.fetch();
    // A refusal, such as a rate limit, carries no events to rewrite.
    if (!response.ok()) return route.fulfill({ response });
    const events = await response.json();
    await route.fulfill({
      response,
      json: events.map((event) =>
        event.kind === 39000 &&
        event.tags.some(
          ([key, id]) =>
            key === "d" && id === "11111111-1111-4111-8111-111111111111",
        )
          ? app.signRelay({
              kind: event.kind,
              created_at: event.created_at,
              content: event.content,
              tags: [
                ...event.tags.filter(([key]) => key !== "join_role"),
                ["join_role", "guest"],
              ],
            })
          : event,
      ),
    });
  });
  await page.goto(app.origin);
  await openPage(page, "Messages");
  await page
    .getByRole("navigation", { name: "Subscribed channels" })
    .getByRole("button", { name: "Lifecycle channel", exact: true })
    .click();
  await page
    .getByRole("button", { name: /^Manage members of /, exact: true })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Manage members",
    exact: true,
  });
  await expect(
    dialog.getByRole("region", { name: "Member list", exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("region", { name: "General access", exact: true }),
  ).toHaveCount(0);
  await animationsSettled(dialog);
  for (const [width, height, scale, theme] of [
    [1440, 950, 1, "light"],
    [1440, 950, 2, "dark"],
    [390, 720, 1.5, "light"],
  ]) {
    await page.setViewportSize({ width, height });
    await page.evaluate(
      ({ scale, theme }) => {
        document.documentElement.style.setProperty(
          "--buzz-text-scale",
          String(scale),
        );
        document.documentElement.setAttribute("data-color-mode", theme);
      },
      { scale, theme },
    );
    await expect
      .poll(() =>
        dialog.locator("footer").evaluate((footer) => ({
          horizontal: footer.scrollWidth > footer.clientWidth + 1,
          vertical: footer.scrollHeight > footer.clientHeight + 1,
        })),
      )
      .toEqual({ horizontal: false, vertical: false });
    const done = dialog.getByRole("button", { name: "Done", exact: true });
    const copy = dialog.getByRole("button", { name: "Copy link", exact: true });
    for (const action of [copy, done]) {
      await action.focus();
      await expect(action).toBeFocused();
      await expect(action).toBeInViewport({ ratio: 1 });
    }
    await dialog.screenshot({
      path: testInfo.outputPath(
        `members-${width}-${height}-${scale}-${theme}.png`,
      ),
    });
  }
  await page.setViewportSize({ width: 1440, height: 950 });
  await page.evaluate(() =>
    document.documentElement.style.setProperty("--buzz-text-scale", "1"),
  );
  const memberActions = dialog.getByRole("button", { name: /^Actions for / });
  await expect(memberActions).toHaveCount(2);
  await memberActions.nth(1).click();
  await page
    .getByRole("menuitemradio", { name: "Viewing only", exact: true })
    .click();
  const roleConfirmation = page.getByRole("dialog", {
    name: "Change access to Viewing only?",
    exact: true,
  });
  await expect(roleConfirmation).toContainText(
    "Change access from Participating to Viewing only.",
  );
  await roleConfirmation
    .getByRole("button", { name: "Cancel", exact: true })
    .click();
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(dialog).toHaveCount(0);

  await openChannelDetails(page);
  const panel = page.getByRole("complementary", {
    name: "Channel settings",
    exact: true,
  });
  const general = panel.getByRole("region", {
    name: "General access",
    exact: true,
  });
  const audience = general.getByRole("combobox", { name: "General access" });
  await expect(audience).toBeEnabled();
  await expect(audience).toHaveText("View only");
  for (const [width, height, scale, theme] of [
    [1440, 950, 1, "light"],
    [1440, 950, 1, "dark"],
    [1440, 950, 2, "dark"],
    [700, 900, 2, "light"],
    [390, 900, 2, "dark"],
    [390, 720, 1, "dark"],
    [390, 720, 1.5, "light"],
  ]) {
    await page.setViewportSize({ width, height });
    await page.evaluate(
      ({ scale, theme }) => {
        document.documentElement.style.setProperty(
          "--buzz-text-scale",
          String(scale),
        );
        document.documentElement.setAttribute("data-color-mode", theme);
      },
      { scale, theme },
    );
    await expect
      .poll(() =>
        general.evaluate((node) => {
          const control = node.querySelector('[role="combobox"]');
          return {
            horizontalOverflow:
              node.scrollWidth > node.clientWidth + 1 ||
              control.scrollWidth > control.clientWidth + 1,
          };
        }),
      )
      .toEqual({ horizontalOverflow: false });
    await audience.scrollIntoViewIfNeeded();
    await expect(audience).toBeInViewport({ ratio: 1 });
    const insets = await audience.evaluate((node) => {
      const style = getComputedStyle(node);
      return [style.paddingInlineStart, style.paddingInlineEnd];
    });
    expect(parseFloat(insets[0])).toBe(16 * scale);
    expect(parseFloat(insets[1])).toBe(16 * scale);
    await audience.click();
    const options = page.getByRole("listbox");
    await expect(options).toBeVisible();
    if (width >= 700 && scale === 1) {
      await expect
        .poll(async () => {
          const popup = await page.locator(".buzz-select-popup").boundingBox();
          const trigger = await audience.boundingBox();
          return Math.abs(popup.x + popup.width - trigger.x - trigger.width);
        })
        .toBeLessThan(1);
    }
    await expect(options.getByRole("option")).toHaveText([
      /Public/,
      /View only/,
      /Private/,
    ]);
    await expect(options.locator(".buzz-select-separator")).toBeVisible();
    for (const name of ["Public", "View only", "Private"]) {
      const option = options.getByRole("option", { name, exact: true });
      // A height-capped popup can end on a fractional pixel, which a minimal
      // "if needed" scroll leaves a sliver short of; center the option instead.
      await option.evaluate((node) => node.scrollIntoView({ block: "center" }));
      await expect(
        option,
        `${name} at ${width}x${height} ${scale}x`,
      ).toBeInViewport({ ratio: 1 });
    }
    await page.keyboard.press("Escape");
    await expect(audience).toBeFocused();
    await panel.screenshot({
      path: testInfo.outputPath(
        `access-${width}-${height}-${scale}-${theme}.png`,
      ),
    });
  }
  await audience.click();
  await page.getByRole("option", { name: "Private", exact: true }).click();
  const confirmation = page.getByRole("alertdialog");
  await expect(confirmation).toBeVisible();
  await confirmation
    .getByRole("button", { name: "Cancel", exact: true })
    .click();
  await expect(audience).toBeFocused();
  expect(app.report.lifecyclePublications ?? []).toEqual([]);
  expect(app.report.unexpected).toEqual([]);
});

// A real rejected/unbound receipt drives the editor's own recovery state. Only
// the browser can prove its feedback does not displace the adjacent controls.
for (const outcome of ["rejected", "uncertain"]) {
  test(`access ${outcome} feedback stays full-width below the policy row`, async ({
    page,
    app,
  }, testInfo) => {
    let publications = 0;
    await page.route(
      "**/api/relay/**/channel-details-publish",
      async (route) => {
        const event = route.request().postDataJSON();
        publications++;
        // Do not forward this disposable write to the fixture relay.
        await route.fulfill({
          json:
            outcome === "rejected"
              ? {
                  accepted: false,
                  event_id: event.id,
                  message:
                    "Access update was rejected. Reload the latest channel access before trying again.",
                }
              : { accepted: true, event_id: "unbound-receipt" },
        });
      },
    );
    await page.goto(app.origin);
    await openPage(page, "Messages");
    await page
      .getByRole("navigation", { name: "Subscribed channels" })
      .getByRole("button", { name: "Lifecycle channel", exact: true })
      .click();
    await openChannelDetails(page);
    const dialog = page.getByRole("complementary", {
      name: "Channel settings",
      exact: true,
    });
    const general = dialog.getByRole("region", {
      name: "General access",
      exact: true,
    });
    const access = general.getByRole("combobox", { name: "General access" });
    await expect(access).toBeEnabled();
    await access.click();
    await page.getByRole("option", { name: "Private", exact: true }).click();
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Change access", exact: true })
      .click();
    const feedbackGroup = dialog.getByRole("group", {
      name: "General access recovery",
      exact: true,
    });
    const recovery = feedbackGroup.getByRole("button", {
      name: outcome === "rejected" ? "Reload access" : "Check save status",
      exact: true,
    });
    await expect(recovery).toBeEnabled();
    await expect(feedbackGroup.getByRole("alert")).toBeVisible();
    if (outcome === "uncertain") {
      await page
        .getByRole("button", { name: "Close Channel settings tab" })
        .click();
      await openChannelDetails(page);
      await expect(recovery).toBeEnabled();
      await expect(
        feedbackGroup.getByText(/Checking never resends it/),
      ).toBeVisible();
    }
    for (const [width, height, scale, theme] of [
      [1440, 950, 1, "light"],
      [1440, 950, 1, "dark"],
      [390, 900, 1.5, "dark"],
    ]) {
      await page.setViewportSize({ width, height });
      await page.evaluate(
        ({ scale, theme }) => {
          document.documentElement.style.setProperty(
            "--buzz-text-scale",
            String(scale),
          );
          document.documentElement.dataset.colorMode = theme;
        },
        { scale, theme },
      );
      await general.scrollIntoViewIfNeeded();
      const choice = await access.boundingBox();
      const feedback =
        outcome === "rejected"
          ? feedbackGroup.getByRole("alert")
          : feedbackGroup.getByText(/Checking never resends it/);
      const alert = await feedback.boundingBox();
      const action = await recovery.boundingBox();
      expect(alert.y).toBeGreaterThanOrEqual(choice.y + choice.height);
      expect(action.y).toBeGreaterThanOrEqual(alert.y + alert.height);
      const bounds = await general.boundingBox();
      const inset = await feedbackGroup.evaluate((node) =>
        parseFloat(getComputedStyle(node).paddingInlineStart),
      );
      expect(alert.x).toBeCloseTo(bounds.x + inset, 0);
      expect(alert.width).toBeCloseTo(bounds.width - 2 * inset, 0);
      await recovery.scrollIntoViewIfNeeded();
      await recovery.focus();
      await expect(recovery).toBeInViewport({ ratio: 1 });
      expect(
        await general.evaluate((node) => node.scrollWidth - node.clientWidth),
      ).toBeLessThanOrEqual(1);
      await dialog.screenshot({
        path: testInfo.outputPath(`access-${outcome}-${theme}-${scale}.png`),
      });
    }
    expect(publications).toBe(1);
    expect(app.report.lifecyclePublications ?? []).toEqual([]);
    expect(app.report.unexpected).toEqual([]);
  });
}
