// Passkeys with Chromium's virtual authenticator (WebAuthn over CDP). The relying
// party is localhost, the host of users.public_url the browser opens the UI on.
import type { Page } from "@playwright/test";

import { createUser, dialog, expect, expectToast, go, nav, signIn, signOut, test, unique } from "./fixtures";

// virtualAuthenticator adds a platform authenticator with user verification that
// holds discoverable credentials, and returns a function listing them.
async function virtualAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  return async () => (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials;
}

test("registers a passkey on the account page and signs in with it", async ({ page }) => {
  const email = `${unique("passkey")}@ui-test.example.com`;
  const password = "passkey-user-password-123";
  await signIn(page);
  await createUser(page, email, password, "viewer");
  await signOut(page);

  const credentials = await virtualAuthenticator(page);
  await signIn(page, email, password);
  await go(page, "Account");
  const card = page.locator(".card").filter({ has: page.getByRole("heading", { level: 2, name: "Passkeys", exact: true }) });
  await expect(card.getByText("No passkeys yet.")).toBeVisible();
  await card.getByRole("button", { name: "Add a passkey" }).click();
  const dlg = dialog(page, "Add a passkey");
  await dlg.getByLabel("Name", { exact: true }).fill("UI test laptop");
  await dlg.getByRole("button", { name: "Continue" }).click();
  await expectToast(page, "Passkey added");
  await expect(card.getByRole("listitem").filter({ hasText: "UI test laptop" })).toBeVisible();
  const stored = await credentials();
  expect(stored).toHaveLength(1);
  expect(stored[0].isResidentCredential).toBe(true);

  // A fresh sign-in page, no email typed: the authenticator offers the passkey.
  await signOut(page);
  await page.reload();
  const form = page.locator("#login-form");
  await form.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(nav(page)).toBeVisible();
  await expect(page.locator("#whoami")).toContainText(email);

  await go(page, "Account");
  await expect(card.getByRole("listitem").filter({ hasText: "UI test laptop" })).toContainText("last used");
});

test("shows a readable error when the passkey prompt fails", async ({ page }) => {
  // No authenticator answers: the user cancels, or the prompt times out.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: false, automaticPresenceSimulation: true },
  });
  await page.goto("/ui/");
  const form = page.locator("#login-form");
  await form.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(form.getByRole("alert")).toHaveText("The passkey prompt was cancelled or timed out.");
  await expect(nav(page)).toBeHidden();
});
