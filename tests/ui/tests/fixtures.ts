// Shared fixtures and helpers. Every test fails on a console error, an uncaught
// exception or a 5xx answer in any page it visits.
import fs from "node:fs";

import { test as base, expect, type Locator, type Page } from "@playwright/test";

import { ADMIN_EMAIL, ADMIN_PASSWORD } from "./env";

export { expect };

type Fixtures = { pageErrors: string[] };

export const test = base.extend<Fixtures>({
  baseURL: async ({}, use) => {
    const url = process.env.TENARIUM_URL;
    if (!url) throw new Error("TENARIUM_URL is not set: run the suite with `npx playwright test` (global setup starts the server)");
    await use(url);
  },
  pageErrors: [async ({ context }, use) => {
    const errors: string[] = [];
    const watch = (page: Page) => {
      page.on("console", (msg) => {
        // The UI calls endpoints that answer 401/403/404 by design (failed sign-ins,
        // features switched off); Chromium logs each as "Failed to load resource".
        // Those statuses are checked through the UI instead, and 5xx answers below.
        if (msg.type() === "error" && !msg.text().startsWith("Failed to load resource")) {
          errors.push(`console error on ${page.url()}: ${msg.text()}`);
        }
      });
      page.on("pageerror", (err) => errors.push(`uncaught exception on ${page.url()}: ${err.message}`));
      page.on("response", (res) => {
        if (res.status() >= 500) errors.push(`${res.status()} from ${res.request().method()} ${res.url()}`);
      });
    };
    context.pages().forEach(watch);
    context.on("page", watch);
    await use(errors);
    expect(errors, "console errors, uncaught exceptions and server errors").toEqual([]);
  }, { auto: true }],
});

// unique returns a lowercase name no other test (or retry) uses.
export function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
}

// signIn opens the UI and signs in with email and password through the form.
export async function signIn(page: Page, email = ADMIN_EMAIL, password = ADMIN_PASSWORD) {
  await page.goto("/ui/");
  const form = page.locator("#login-form");
  await form.getByRole("textbox", { name: "Email", exact: true }).fill(email);
  await form.getByRole("textbox", { name: "Password", exact: true }).fill(password);
  await form.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(nav(page)).toBeVisible();
}

export const nav = (page: Page) => page.getByRole("navigation", { name: "Main" });

// go opens a page from the sidebar and waits for its heading.
export async function go(page: Page, link: string, heading = link) {
  await nav(page).getByRole("link", { name: link, exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
}

export const dialog = (page: Page, name: string | RegExp) => page.getByRole("dialog", { name });

export async function expectToast(page: Page, text: string | RegExp) {
  await expect(page.locator("#toast")).toContainText(text);
}

// field finds a form control by its exact label inside a dialog or form.
export const field = (scope: Locator, label: string) => scope.getByLabel(label, { exact: true });

// emailsTo returns the emails the server logged for address (the default mailer
// writes them to the log instead of sending them).
export function emailsTo(address: string): { subject: string; text: string }[] {
  const log = process.env.TENARIUM_LOG;
  if (!log) throw new Error("TENARIUM_LOG is not set");
  return fs.readFileSync(log, "utf8").split("\n").flatMap((line) => {
    if (!line.includes("email (not sent")) return [];
    try {
      const rec = JSON.parse(line);
      const to = Array.isArray(rec.to) ? rec.to : [rec.to];
      return to.includes(address) ? [{ subject: rec.subject, text: rec.text }] : [];
    } catch {
      return [];
    }
  });
}

// expectNoHorizontalScroll checks the page is not wider than the viewport.
export async function expectNoHorizontalScroll(page: Page) {
  const { scroll, client } = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth,
  }));
  expect(scroll, `page is ${scroll}px wide in a ${client}px viewport`).toBeLessThanOrEqual(client);
}

// signOut uses the sidebar's button (session lists have "Sign out" buttons too).
export async function signOut(page: Page) {
  await page.locator("#app aside").getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.locator("#login-form")).toBeVisible();
}

// createTenant fills the New tenant dialog and waits for the tenant's page.
export async function createTenant(page: Page, slug: string, opts: { template?: string; plan?: string; labels?: string; parent?: string } = {}) {
  await go(page, "Tenants");
  await page.getByRole("button", { name: "New tenant" }).click();
  const dlg = dialog(page, "New tenant");
  if (opts.template) await field(dlg, "Template").selectOption({ label: opts.template });
  await field(dlg, "Name").fill(`Tenant ${slug}`);
  await field(dlg, "Slug").fill(slug);
  if (opts.plan) await field(dlg, "Plan").selectOption({ label: opts.plan });
  if (opts.parent) await field(dlg, "Parent tenant").fill(opts.parent);
  if (opts.labels) await field(dlg, "Labels").fill(opts.labels);
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(dlg).toBeHidden();
  await expectToast(page, `Tenant ${slug} created`);
  await expect(page.getByRole("heading", { level: 1, name: new RegExp(`Tenant ${slug}`) })).toBeVisible();
}

// createUser adds a user with a password on the Users page.
export async function createUser(page: Page, email: string, password: string, roles = "") {
  await go(page, "Users");
  await page.getByRole("button", { name: "New user" }).click();
  const dlg = dialog(page, "New user");
  await field(dlg, "Email").fill(email);
  await field(dlg, "Name").fill("UI Test User");
  await field(dlg, "Platform roles").fill(roles);
  await field(dlg, "Password").fill(password);
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(dlg).toBeHidden();
  await expectToast(page, "User created");
}

// tabTo presses Tab until target has the keyboard focus.
export async function tabTo(page: Page, target: Locator, max = 40) {
  await expect(target).toBeVisible();
  for (let i = 0; i < max; i++) {
    await page.keyboard.press("Tab");
    if (await target.evaluate((el) => el === document.activeElement)) return;
  }
  throw new Error(`${target} was not reached with ${max} Tab presses`);
}
