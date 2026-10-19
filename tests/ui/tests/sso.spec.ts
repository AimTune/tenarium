// Tenant single sign-on with OpenID Connect against the fake provider
// (fakes/idp.ts): the tenant proves its email domain with a DNS TXT record (the
// fake DNS answers for the test server), configures the connection, and its users
// sign in through the provider.
import { CLIENT_SECRET, issuer, publishTXT, signInAtIdP } from "../fakes/client";
import { createTenant, dialog, expect, expectToast, field, nav, signIn, signOut, test, unique } from "./fixtures";

test("configures OIDC single sign-on for a tenant and signs in through it", async ({ page, context }) => {
  await signIn(page);
  const slug = unique("sso");
  const domain = `${slug}.example.com`;
  await createTenant(page, slug, { plan: "Pro (pro)" });

  // The domain: added, refused before its TXT record exists, verified after.
  await page.getByRole("tab", { name: "Domains" }).click();
  await page.getByRole("button", { name: "Add domain" }).click();
  const adlg = dialog(page, "Add domain");
  await field(adlg, "Hostname").fill(domain);
  await adlg.getByRole("button", { name: "Add" }).click();
  const vdlg = dialog(page, `Verify ${domain}`);
  await expect(vdlg).toBeVisible();
  const record = vdlg.locator("dl.kv dd");
  await expect(record.nth(0)).toHaveText("TXT");
  const name = (await record.nth(1).locator("code").textContent())!.trim();
  const value = (await record.nth(2).locator("code").textContent())!.trim();
  expect(name).toBe(`_tenarium-challenge.${domain}`);
  await vdlg.getByRole("button", { name: "Done" }).click();
  await expect(vdlg).toBeHidden();

  const row = page.getByRole("row", { name: new RegExp(domain.replaceAll(".", "\\.")) });
  await expect(row).toContainText("unverified");
  await row.getByRole("button", { name: "Verify" }).click();
  await expectToast(page, /verification TXT record not found/);
  await publishTXT(name, value);
  await row.getByRole("button", { name: "Verify" }).click();
  await expectToast(page, "Domain verified");
  await expect(row).toContainText("verified");

  // The connection; email domains must be verified domains of the tenant.
  await page.getByRole("tab", { name: "SSO" }).click();
  await page.getByRole("button", { name: "Configure SSO" }).click();
  const sdlg = dialog(page, "Configure SSO");
  await field(sdlg, "Issuer URL").fill(issuer(slug));
  await field(sdlg, "Client ID").fill(`tenarium-${slug}`);
  await field(sdlg, "Client secret").fill(CLIENT_SECRET);
  await field(sdlg, "Email domains").fill(`other-${domain}`);
  await field(sdlg, "Auto-provision members").check();
  await sdlg.getByRole("button", { name: "Save" }).click();
  await expect(sdlg.getByRole("alert")).toContainText("must first be added and verified as a domain of this tenant");
  await field(sdlg, "Email domains").fill(domain);
  await sdlg.getByRole("button", { name: "Save" }).click();
  await expect(sdlg).toBeHidden();
  await expectToast(page, "SSO connection saved");
  await expect(page.getByText(issuer(slug), { exact: true })).toBeVisible();
  await signOut(page);

  // A user of the domain signs in through the provider and becomes a member.
  const email = `ada@${domain}`;
  await signInAtIdP(context, { email, email_verified: true, name: "Ada Lovelace" });
  const form = page.locator("#login-form");
  await form.getByLabel("Sign in with").selectOption("sso");
  await form.getByRole("textbox", { name: "Email", exact: true }).fill(email);
  await form.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(nav(page)).toBeVisible();
  await expect(page.locator("#whoami")).toContainText(email);
  await expect(page.locator("#whoami")).toContainText("tenant");
  expect(page.url()).not.toContain("access_token");

  // An address the provider has not verified is refused.
  await signOut(page);
  await signInAtIdP(context, { email: `bob@${domain}`, email_verified: false });
  await form.getByLabel("Sign in with").selectOption("sso");
  await form.getByRole("textbox", { name: "Email", exact: true }).fill(`bob@${domain}`);
  await form.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(form.getByRole("alert")).toHaveText("The identity provider's answer was rejected.");
  await expect(nav(page)).toBeHidden();
});

test("explains when an email has no single sign-on", async ({ page }) => {
  await page.goto("/ui/");
  const form = page.locator("#login-form");
  await form.getByLabel("Sign in with").selectOption("sso");
  await form.getByRole("textbox", { name: "Email", exact: true }).fill(`nobody@${unique("nosso")}.example.com`);
  await form.getByRole("button", { name: "Sign in", exact: true }).click();
  // The error stays in the form instead of a raw JSON page.
  await expect(form.getByRole("alert")).toBeVisible();
  await expect(form.getByRole("alert")).not.toBeEmpty();
  expect(new URL(page.url()).pathname).toBe("/ui/");
});
