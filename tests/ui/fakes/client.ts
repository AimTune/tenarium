// Test-side helpers for the fake OpenID provider and DNS (fakes/idp.ts), which
// the global setup runs; its address reaches the tests through FAKE_IDP_URL.
import type { BrowserContext } from "@playwright/test";

import { CLIENT_SECRET, USER_COOKIE, type FakeUser } from "./idp";

export { CLIENT_SECRET, type FakeUser };

export function fakeIdPURL(): string {
  const url = process.env.FAKE_IDP_URL;
  if (!url) throw new Error("FAKE_IDP_URL is not set: run the suite with `npx playwright test`");
  return url;
}

// issuer is the issuer URL of a realm of the fake provider ("social" is the
// realm the server's social login provider uses).
export const issuer = (realm: string) => `${fakeIdPURL()}/${realm}`;

// signInAtIdP makes the fake provider sign this browser context in as user.
export async function signInAtIdP(context: BrowserContext, user: FakeUser) {
  await context.addCookies([{
    name: USER_COOKIE, value: Buffer.from(JSON.stringify(user)).toString("base64url"), url: fakeIdPURL(),
  }]);
}

// publishTXT adds a DNS TXT record the server's domain verification will find.
export async function publishTXT(name: string, value: string) {
  const res = await fetch(`${fakeIdPURL()}/dns/txt`, { method: "POST", body: JSON.stringify({ name, value }) });
  if (!res.ok) throw new Error(`fake dns: ${res.status}`);
}
