import { ADMIN_EMAIL, ADMIN_PASSWORD } from "./env";
import { emailsTo, expect, expectToast, go, nav, signIn, signOut, test } from "./fixtures";

test("signs in with email and password and signs out", async ({ page }) => {
  await signIn(page);
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await expect(page.locator("#whoami")).toContainText(ADMIN_EMAIL);
  await expect(nav(page).getByRole("link", { name: "Dashboard" })).toHaveAttribute("aria-current", "page");

  await signOut(page);
  await expect(page.locator("#login-form").getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
  await expect(nav(page)).toBeHidden();
});

test("shows an error for a wrong password", async ({ page }) => {
  await page.goto("/ui/");
  const form = page.locator("#login-form");
  await form.getByRole("textbox", { name: "Email", exact: true }).fill(ADMIN_EMAIL);
  await form.getByRole("textbox", { name: "Password", exact: true }).fill("not-the-right-password");
  await form.getByRole("button", { name: "Sign in", exact: true }).click();
  const alert = form.getByRole("alert");
  await expect(alert).toBeVisible();
  await expect(alert).not.toBeEmpty();
  await expect(nav(page)).toBeHidden();
});

test("switches the language to Turkish and back", async ({ page }) => {
  await page.goto("/ui/");
  const login = page.locator("#login-form");
  await login.getByLabel("Language").selectOption("tr");
  await expect(login.getByRole("button", { name: "Oturum aç", exact: true })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "tr");

  // The form is in Turkish now.
  await login.getByRole("textbox", { name: "E-posta", exact: true }).fill(ADMIN_EMAIL);
  await login.getByRole("textbox", { name: "Parola", exact: true }).fill(ADMIN_PASSWORD);
  await login.getByRole("button", { name: "Oturum aç", exact: true }).click();
  const menu = page.getByRole("navigation", { name: "Ana menü" });
  await expect(menu.getByRole("link", { name: "Kiracılar" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Pano" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Oturumu kapat" })).toBeVisible();

  // The choice is remembered across reloads.
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "Pano" })).toBeVisible();

  await page.locator("#app").getByLabel("Dil").selectOption("en");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(nav(page).getByRole("link", { name: "Tenants" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1, name: "Dashboard" })).toBeVisible();
  await go(page, "Plans");
});

test("signs in with an emailed sign-in link", async ({ page }) => {
  await page.goto("/ui/");
  const form = page.locator("#login-form");
  const before = emailsTo(ADMIN_EMAIL).length;
  await form.getByRole("textbox", { name: "Email", exact: true }).fill(ADMIN_EMAIL);
  await form.getByRole("button", { name: "Email me a sign-in link" }).click();
  await expectToast(page, `If an account exists for ${ADMIN_EMAIL}, a sign-in link is on its way.`);

  let link = "";
  await expect.poll(() => {
    const mails = emailsTo(ADMIN_EMAIL).slice(before);
    link = mails.map((m) => /#\/magic\/([\w.-]+)/.exec(m.text)?.[1]).find(Boolean) || "";
    return link;
  }, { message: "the sign-in email in the server log" }).not.toBe("");

  await page.goto(`/ui/#/magic/${link}`);
  await expect(nav(page)).toBeVisible();
  await expect(page.locator("#whoami")).toContainText(ADMIN_EMAIL);
  // The token left the address bar and cannot be used again.
  expect(page.url()).not.toContain(link);
});
