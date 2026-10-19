// Social login with the "FakeID" provider of the server's config (an OpenID
// provider of type oidc, served by fakes/idp.ts): the button round trip ends with
// the session in the URL fragment, which the UI takes and removes.
import { signInAtIdP } from "../fakes/client";
import { createUser, expect, nav, signIn, signOut, test, unique } from "./fixtures";

test("signs in with a social login provider", async ({ page, context }) => {
  // A platform user (without a tenant, a user needs a platform role to sign in).
  const email = `${unique("social")}@ui-test.example.com`;
  await signIn(page);
  await createUser(page, email, "social-user-password-123", "viewer");
  await signOut(page);

  await signInAtIdP(context, { email, email_verified: true, name: "Grace Hopper" });
  await page.goto("/ui/");
  const form = page.locator("#login-form");
  await expect(form.getByText("or continue with")).toBeVisible();
  await form.getByRole("button", { name: "FakeID" }).click();
  await expect(nav(page)).toBeVisible();
  await expect(page.locator("#whoami")).toContainText(email);
  // The tokens left the address bar.
  expect(page.url()).not.toContain("access_token");
  expect(new URL(page.url()).hash).not.toContain("token");

  // The session survives a reload.
  await page.reload();
  await expect(page.locator("#whoami")).toContainText(email);
});

test("explains refused social logins", async ({ page, context }) => {
  const email = `${unique("social")}@ui-test.example.com`;
  const form = page.locator("#login-form");
  const fakeID = form.getByRole("button", { name: "FakeID" });

  // The provider has not verified the address.
  await signInAtIdP(context, { email, email_verified: false });
  await page.goto("/ui/");
  await fakeID.click();
  await expect(form.getByRole("alert")).toHaveText("The provider has not verified your email address.");
  await expect(nav(page)).toBeHidden();
  expect(page.url()).not.toContain("error=");

  // A verified address of a new user: the user is created, but without a platform
  // role or membership there is nothing to sign in to.
  await signInAtIdP(context, { email, email_verified: true });
  await fakeID.click();
  await expect(form.getByRole("alert")).toHaveText("Enter a tenant to sign in to.");
  await expect(nav(page)).toBeHidden();
});
