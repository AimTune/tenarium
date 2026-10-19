// Clickable table rows work from the keyboard: each has a link (rows that open a
// page) or a button (rows that open a dialog or show details) to Tab to and press.
import { createTenant, createUser, dialog, expect, go, signIn, tabTo, test, unique } from "./fixtures";

test("tenant rows open the tenant with Tab and Enter", async ({ page }) => {
  await signIn(page);
  const parent = unique("kbd");
  const child = unique("kbd-child");
  await createTenant(page, parent);
  await createTenant(page, child, { parent });

  await go(page, "Tenants");
  const search = page.getByRole("searchbox", { name: "Filter by slug or name" });
  await search.fill(parent);
  await search.focus();
  const row = page.getByRole("link", { name: new RegExp(`Tenant ${parent}`) });
  await tabTo(page, row);
  await expect(row).toHaveAttribute("href", /^#\/tenant\//);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: new RegExp(`Tenant ${parent}`) })).toBeVisible();

  // The Children tab lists the child; its row opens it the same way.
  await page.getByRole("tab", { name: "Children" }).click();
  const childRow = page.getByRole("link", { name: new RegExp(`Tenant ${child}`) });
  await childRow.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: new RegExp(`Tenant ${child}`) })).toBeVisible();
});

test("user rows open the user dialog with Tab and Enter", async ({ page }) => {
  await signIn(page);
  const email = `${unique("kbd")}@ui-test.example.com`;
  await createUser(page, email, "keyboard-password-123");
  const search = page.getByRole("searchbox", { name: "Search email or name" });
  await search.fill(email);
  await expect(page.getByRole("row")).toHaveCount(2);
  await search.focus();
  await tabTo(page, page.getByRole("button", { name: new RegExp(email) }));
  await page.keyboard.press("Enter");
  const dlg = dialog(page, email);
  await expect(dlg).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dlg).toBeHidden();
});

test("event, schema and audit rows show their details with Enter and Space", async ({ page }) => {
  await signIn(page);

  // Events: the details stay open (and focused) while new events arrive.
  await go(page, "Events");
  const first = page.locator("tbody").getByRole("button").first();
  await expect(first).toBeVisible();
  const seq = (await first.textContent())!.trim();
  const toggle = page.locator("tbody").getByRole("button", { name: seq, exact: true });
  await page.getByRole("searchbox", { name: "Type filter, e.g. tenant.*" }).focus();
  await tabTo(page, toggle);
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await page.keyboard.press("Enter");
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  const details = page.locator("tbody tr:not(.clickable)").filter({ hasText: `"seq": ${seq}` });
  await expect(details).toBeVisible();
  await page.waitForTimeout(3_500); // past the next 3s refresh
  await expect(toggle).toBeFocused();
  await expect(details).toBeVisible();
  await page.keyboard.press(" ");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(details).toBeHidden();

  // Event schemas.
  await go(page, "Event schemas");
  const filter = page.getByRole("searchbox", { name: "Filter by type" });
  await filter.fill("tenant.created");
  await filter.focus();
  const schema = page.locator("tbody").getByRole("button", { name: "tenant.created" }).first();
  await tabTo(page, schema);
  await page.keyboard.press("Enter");
  await expect(schema).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("tbody pre").first()).toBeVisible();

  // Audit.
  await go(page, "Audit");
  await page.getByRole("button", { name: "Search" }).focus();
  const entry = page.locator("tbody").getByRole("button").first();
  await tabTo(page, entry);
  await page.keyboard.press(" ");
  await expect(entry).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("tbody pre").first()).toBeVisible();
});
