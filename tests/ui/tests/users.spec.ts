import crypto from "node:crypto";

import { ADMIN_EMAIL } from "./env";
import { createUser, dialog, expect, expectToast, field, go, nav, signIn, signOut, test, unique } from "./fixtures";

// totp computes an RFC 6238 code (SHA-1, 6 digits, 30 s) for a base32 secret.
function totp(secret: string, step = Math.floor(Date.now() / 30_000)): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const sum = crypto.createHmac("sha1", key).update(msg).digest();
  const off = sum[sum.length - 1] & 0x0f;
  return String((sum.readUInt32BE(off) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("lists users, creates one and shows sessions", async ({ page }) => {
  await signIn(page);
  await go(page, "Users");
  const admin = page.getByRole("row", { name: new RegExp(ADMIN_EMAIL) });
  await expect(admin).toContainText("admin");
  await expect(admin).toContainText("active");

  const email = `${unique("user")}@ui-test.example.com`;
  await createUser(page, email, "another-password-123");
  await page.getByRole("searchbox", { name: "Search email or name" }).fill(email);
  await expect(page.getByRole("row")).toHaveCount(2); // header + the user
  await expect(page.getByRole("row", { name: new RegExp(email) })).toContainText("active");

  // The admin's own sessions include this browser.
  await page.getByRole("searchbox", { name: "Search email or name" }).fill(ADMIN_EMAIL);
  await page.getByRole("row", { name: new RegExp(ADMIN_EMAIL) }).click();
  const udlg = dialog(page, ADMIN_EMAIL);
  await expect(field(udlg, "Platform roles")).toHaveValue("admin");
  await udlg.getByRole("button", { name: "Sessions" }).click();
  const sdlg = dialog(page, `Sessions of ${ADMIN_EMAIL}`);
  await expect(sdlg.getByRole("listitem").first()).toBeVisible();
  await expect(sdlg.getByRole("listitem").first()).toContainText(/Chrome on \w+/);
  await expect(sdlg.getByRole("button", { name: "Sign out" }).first()).toBeVisible();
  await sdlg.getByRole("button", { name: "Close" }).click();
  await expect(sdlg).toBeHidden();
});

test("account page: sessions and two-factor enrollment", async ({ page }) => {
  await signIn(page);
  const email = `${unique("mfa")}@ui-test.example.com`;
  const password = "mfa-user-password-123";
  await createUser(page, email, password, "viewer");
  await signOut(page);

  await signIn(page, email, password);
  await go(page, "Account");
  const card = (title: string) => page.locator(".card").filter({ has: page.getByRole("heading", { level: 2, name: title, exact: true }) });
  await expect(card("Email address")).toContainText(email);
  await expect(card("Sessions").getByRole("listitem").first()).toContainText(/Chrome on \w+/);
  await expect(card("Passkeys")).toBeVisible();
  await expect(card("Two-factor authentication")).toContainText("off");

  // Enroll with a code computed from the shown secret.
  await card("Two-factor authentication").getByRole("button", { name: "Set up" }).click();
  const dlg = dialog(page, "Set up two-factor authentication");
  const secret = (await dlg.locator("code.secret").first().textContent())!.trim();
  expect(secret).toMatch(/^[A-Z2-7]+=*$/);
  await field(dlg, "Code from your authenticator app").fill("000000"); // almost surely wrong
  await dlg.getByRole("button", { name: "Confirm" }).click();
  await expect(dlg.getByRole("alert")).toBeVisible();
  const step = Math.floor(Date.now() / 30_000);
  await field(dlg, "Code from your authenticator app").fill(totp(secret, step));
  await dlg.getByRole("button", { name: "Confirm" }).click();
  await expectToast(page, "Two-factor authentication enabled");
  const codes = dialog(page, "Recovery codes");
  await expect(codes.locator("pre")).not.toBeEmpty();
  await codes.getByRole("button", { name: "Done" }).click();
  await expect(codes).toBeHidden();
  await expect(card("Two-factor authentication")).toContainText("enabled");
  await expect(card("Two-factor authentication")).toContainText("Recovery codes left");

  // Signing in now asks for a code (a fresh step: codes cannot be replayed).
  await signOut(page);
  const form = page.locator("#login-form");
  await form.getByRole("textbox", { name: "Email", exact: true }).fill(email);
  await form.getByRole("textbox", { name: "Password", exact: true }).fill(password);
  await form.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(form.getByRole("alert")).toHaveText("Enter the code from your authenticator app.");
  await form.getByLabel("Code from your authenticator app").fill(totp(secret, step + 1));
  await form.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(nav(page)).toBeVisible();
  await expect(page.locator("#whoami")).toContainText(email);
});
