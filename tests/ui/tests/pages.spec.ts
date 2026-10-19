import { dialog, expect, expectNoHorizontalScroll, field, go, nav, signIn, test, unique } from "./fixtures";

test("dashboard shows tiles and cards", async ({ page }) => {
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("link", { name: /Tenants$/ }).locator(".tile-value")).toHaveText(/^\d+\+?$/);
  await expect(page.locator(".tile").filter({ hasText: "Dead letters" })).toBeVisible();
  for (const title of ["Tenants by status", "Tenants by plan", "Near their limits", "Recent activity"]) {
    await expect(page.getByRole("heading", { level: 2, name: title })).toBeVisible();
  }
  await expect(page.getByText("Checking usage…")).toBeHidden();
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("heading", { level: 2, name: "Recent activity" })).toBeVisible();
});

test("operations pages render", async ({ page }) => {
  await signIn(page);

  await go(page, "Events");
  await expect(page.getByRole("searchbox", { name: "Type filter, e.g. tenant.*" })).toBeVisible();
  // The seeded plans and admin produced events; a row opens its details.
  const firstEvent = page.locator("tbody tr.clickable").first();
  await expect(firstEvent).toBeVisible();
  await firstEvent.click();
  await expect(page.locator("tbody pre").first()).toBeVisible();

  await page.getByRole("link", { name: "Event schemas" }).first().click();
  await expect(page.getByRole("heading", { level: 1, name: "Event schemas" })).toBeVisible();
  await page.getByRole("searchbox", { name: "Filter by type" }).fill("tenant.created");
  await expect(page.getByRole("row", { name: /tenant\.created/ }).first()).toBeVisible();

  await go(page, "Dead letters");
  await expect(page.getByText(/Undelivered events: \d+/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Replay events" })).toBeVisible();

  await go(page, "Audit");
  await expect(page.getByRole("button", { name: "Search" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Actor" })).toBeVisible();

  await go(page, "Plugins");
  await expect(page.getByText(/Compiled in: /)).toBeVisible();

  await go(page, "Signing keys");
  await expect(page.getByRole("cell", { name: "active" }).first()).toBeVisible();

  await go(page, "OAuth clients");
  await expect(page.getByRole("button", { name: "Register an application" })).toBeVisible();
});

test("leaving the events page stops its live updates", async ({ page }) => {
  await signIn(page);
  // Hold the first poll so the page is left while it is still loading.
  let calls = 0;
  await page.route((url) => url.pathname === "/v1/events", async (route) => {
    calls++;
    await new Promise((r) => setTimeout(r, 1_000));
    await route.continue().catch(() => {});
  });
  await nav(page).getByRole("link", { name: "Events", exact: true }).click();
  await expect.poll(() => calls).toBe(1);
  await go(page, "Plans");
  await page.waitForTimeout(5_000); // more than the 3s refresh interval after the held poll
  expect(calls, "requests to /v1/events after leaving the page").toBe(1);
});

test.describe("on a 375px wide phone", () => {
  test.use({ viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true });

  test("main pages do not scroll sideways", async ({ page }) => {
    await page.goto("/ui/");
    await expect(page.locator("#login-form")).toBeVisible();
    await expectNoHorizontalScroll(page);

    await signIn(page);
    const pages: [string, string][] = [
      ["Dashboard", "Dashboard"], ["Tenants", "Tenants"], ["Plans", "Plans"], ["Templates", "Tenant templates"],
      ["Rollouts", "Feature rollouts"], ["Users", "Users"], ["Events", "Events"], ["Event schemas", "Event schemas"],
      ["Dead letters", "Dead letters"], ["Plugins", "Plugins"], ["Audit", "Audit"], ["OAuth clients", "OAuth clients"],
      ["Signing keys", "Signing keys"], ["Account", "Account"],
    ];
    const wide: string[] = [];
    const check = async (what: string) => {
      await page.waitForLoadState("networkidle");
      const { scroll, client } = await page.evaluate(() => ({
        scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth }));
      if (scroll > client) wide.push(`${what}: ${scroll}px`);
    };
    for (const [link, heading] of pages) {
      await go(page, link, heading);
      await check(`${link} page`);
    }

    // A tenant (created on the phone) and its tabs.
    await go(page, "Tenants");
    await page.getByRole("button", { name: "New tenant" }).click();
    const dlg = dialog(page, "New tenant");
    const slug = unique("phone");
    await field(dlg, "Name").fill(`Phone ${slug}`);
    await field(dlg, "Slug").fill(slug);
    await check("New tenant dialog");
    await dlg.getByRole("button", { name: "Create" }).click();
    await expect(page.getByRole("tablist")).toBeVisible();
    for (const tab of ["Overview", "Members", "Roles & groups", "Usage", "Schedule", "Domains", "API keys", "Webhooks", "SSO", "Audit"]) {
      await page.getByRole("tab", { name: tab, exact: true }).click();
      await check(`tenant ${tab} tab`);
    }
    expect(wide, "pages wider than the 375px viewport").toEqual([]);
    await expect(nav(page)).toBeVisible();
  });
});
