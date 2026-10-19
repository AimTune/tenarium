import type { Page } from "@playwright/test";

import { createTenant, dialog, expect, expectToast, field, go, signIn, test, unique } from "./fixtures";

const card = (page: Page, title: string) => page.locator(".card").filter({ has: page.getByRole("heading", { level: 2, name: title, exact: true }) });

test("creates a tenant from a template and manages it", async ({ page }) => {
  await signIn(page);

  // A template whose labels and plan the new tenant inherits.
  const tpl = unique("tpl");
  await go(page, "Templates", "Tenant templates");
  await page.getByRole("button", { name: "New template" }).click();
  const tdlg = dialog(page, "New template");
  await field(tdlg, "ID").fill(tpl);
  await field(tdlg, "Name").fill(`Template ${tpl}`);
  await field(tdlg, "Plan").selectOption("pro");
  await field(tdlg, "Region").selectOption("us");
  await field(tdlg, "Labels").fill("tier=startup");
  await tdlg.getByRole("button", { name: "Save" }).click();
  await expect(tdlg).toBeHidden();
  await expect(page.getByRole("row", { name: new RegExp(tpl) })).toBeVisible();

  const slug = unique("acme");
  await createTenant(page, slug, { template: `Template ${tpl}` });
  const details = card(page, "Details");
  await expect(details.getByText("tier=startup")).toBeVisible();
  const placement = card(page, "Plan & placement");
  await expect(placement.getByText("pro", { exact: true })).toBeVisible();
  await expect(placement.getByText("us", { exact: true })).toBeVisible();

  // Health.
  const health = card(page, "Health");
  await expect(health.locator(".health-score")).toHaveText(/^\d+$/);
  await expect(health.getByText(/healthy|at risk|critical/)).toBeVisible();

  // Labels.
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const edlg = dialog(page, `Edit ${slug}`);
  await field(edlg, "Labels (replaces all)").fill("tier=gold\nenv=test");
  await edlg.getByRole("button", { name: "Save" }).click();
  await expect(edlg).toBeHidden();
  await expectToast(page, "Saved");
  await expect(details.getByText("env=test")).toBeVisible();
  await expect(details.getByText("tier=gold")).toBeVisible();
  await expect(details.getByText("tier=startup")).toBeHidden();

  // Branding.
  const branding = card(page, "Branding");
  await expect(branding.getByText("No branding: the default look is used.")).toBeVisible();
  await branding.getByRole("button", { name: "Edit branding" }).click();
  const bdlg = dialog(page, "Edit branding");
  await field(bdlg, "Display name").fill("Acme Cloud");
  await field(bdlg, "Primary color").fill("not-a-color");
  await bdlg.getByRole("button", { name: "Save" }).click();
  await expect(bdlg.getByRole("alert")).toHaveText("Colors must look like #4f46e5 or #fff.");
  await field(bdlg, "Primary color").fill("#123abc");
  await bdlg.getByRole("button", { name: "Save" }).click();
  await expect(bdlg).toBeHidden();
  await expectToast(page, "Branding saved");
  await expect(branding.getByText("Acme Cloud")).toBeVisible();
  await expect(branding.getByText("#123abc")).toBeVisible();

  // Maintenance: the banner appears and goes away again.
  await page.getByRole("button", { name: "Maintenance", exact: true }).click();
  const mdlg = dialog(page, "Start maintenance");
  await field(mdlg, "Message").fill("Moving to a new region.");
  await mdlg.getByRole("button", { name: "Start maintenance" }).click();
  await expect(mdlg).toBeHidden();
  await expectToast(page, "Maintenance started");
  const banner = page.getByRole("status").filter({ hasText: "Under maintenance" });
  await expect(banner).toBeVisible();
  await expect(banner).toContainText("Moving to a new region.");
  await page.getByRole("button", { name: "End maintenance" }).click();
  await expectToast(page, "Maintenance ended");
  await expect(banner).toBeHidden();
  await expect(page.getByRole("button", { name: "Maintenance", exact: true })).toBeVisible();

  // The tenant is listed, and the list opens it again.
  await go(page, "Tenants");
  await page.getByRole("searchbox", { name: "Filter by slug or name" }).fill(slug);
  await page.getByRole("row", { name: new RegExp(slug) }).click();
  await expect(page.getByRole("heading", { level: 1, name: new RegExp(`Tenant ${slug}`) })).toBeVisible();
});

test("manages members and API keys of a tenant", async ({ page }) => {
  await signIn(page);
  const slug = unique("team");
  await createTenant(page, slug, { plan: "Pro (pro)" });

  // Members: a new address gets an invitation.
  await page.getByRole("tab", { name: "Members" }).click();
  await expect(page.getByRole("tab", { name: "Members" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("button", { name: "Add member" }).click();
  const adlg = dialog(page, "Add member");
  const email = `${slug}@ui-test.example.com`;
  await field(adlg, "Email").fill(email);
  await field(adlg, "Role").selectOption("admin");
  await field(adlg, "Name").fill("Invited Person");
  await adlg.getByRole("button", { name: "Add" }).click();
  await expect(adlg).toBeHidden();
  await expectToast(page, "Invitation sent");
  const row = page.getByRole("row", { name: new RegExp(email) });
  await expect(row).toContainText("admin");
  await expect(row).toContainText("invited");

  await row.getByRole("button", { name: "Role" }).click();
  const rdlg = dialog(page, "Change role");
  await field(rdlg, "Role").selectOption("viewer");
  await rdlg.getByRole("button", { name: "Save" }).click();
  await expectToast(page, "Role updated");
  await expect(row).toContainText("viewer");

  await row.getByRole("button", { name: "Remove" }).click();
  await dialog(page, "Remove member").getByRole("button", { name: "Remove" }).click();
  await expectToast(page, "Member removed");
  await expect(row).toBeHidden();

  // API keys: the key is shown once, then it can be revoked.
  await page.getByRole("tab", { name: "API keys" }).click();
  await page.getByRole("button", { name: "New API key" }).click();
  const kdlg = dialog(page, "New API key");
  await field(kdlg, "Name").fill("CI deploys");
  await field(kdlg, "Expires in").fill("720h");
  await kdlg.getByRole("button", { name: "Create" }).click();
  const sdlg = dialog(page, "API key CI deploys");
  await expect(sdlg.getByText("Copy the key now. It is not shown again.")).toBeVisible();
  await expect(sdlg.locator("code.secret")).not.toBeEmpty();
  await sdlg.getByRole("button", { name: "Done" }).click();
  await expect(sdlg).toBeHidden();

  const key = page.getByRole("row", { name: /CI deploys/ });
  await expect(key).toContainText("active");
  await key.getByRole("button", { name: "Revoke" }).click();
  await dialog(page, "Revoke key").getByRole("button", { name: "Revoke" }).click();
  await expectToast(page, "Key revoked");
  await expect(key).toContainText("revoked");

  // The tab is part of the address, so a reload stays on it.
  await page.reload();
  await expect(page.getByRole("tab", { name: "API keys" })).toHaveAttribute("aria-selected", "true");
});
