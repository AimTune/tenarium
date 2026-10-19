import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import {
  definePlugin,
  InvalidCredentialsError,
  NotFoundError,
  serve,
  UnsupportedError,
  type Message,
  type User,
} from "../src/index.ts";

const SECRET = "s3cret";
const passwords = new Map<string, string>();
const outbox: Message[] = [];

const plugin = definePlugin({
  manifest: { id: "dir-test", name: "Directory test", version: "0.0.0" },
  init(r) {
    r.userDirectory({
      createUser: (u: User) => (u.email === "empty@example.com" ? "" : `ext-${u.email}`),
      updateUser: (u: User) => {
        if (u.external_id === "missing") throw new NotFoundError();
      },
      deleteUser: () => {},
      setPassword: (u: User, pw: string) => {
        if (u.email.endsWith("@sso.example")) throw new UnsupportedError();
        passwords.set(u.external_id ?? "", pw);
      },
      verifyPassword: (u: User, pw: string) => {
        if (passwords.get(u.external_id ?? "") !== pw) throw new InvalidCredentialsError();
      },
    });
    r.mailer({
      send: async (m: Message) => {
        if (m.subject === "boom") throw new Error("smtp down");
        outbox.push(m);
      },
    });
  },
});

let server: Server;
let base: string;

const call = async (path: string, body: unknown, secret = SECRET) => {
  const res = await fetch(base + path, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
};

const user = (over: Partial<User> = {}): User => ({
  id: "u1", email: "alice@example.com", status: "active", email_verified: true, directory: "x", version: 1,
  external_id: "ext-alice@example.com", ...over,
});

before(async () => {
  server = await serve(plugin, { addr: "127.0.0.1:0", secret: SECRET });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
  process.removeAllListeners("SIGINT");
  process.removeAllListeners("SIGTERM");
});

test("init declares the directory and mailer", async () => {
  const { status, body } = await call("/init", { protocol: 1, instance: "dirs", config: {} });
  assert.equal(status, 200);
  // verifyPassword is implemented, sendInvitation is not; names default to the instance.
  assert.deepEqual(body.user_directory, { verify_password: true });
  assert.deepEqual(body.mailer, {});
});

test("directory operations", async () => {
  assert.deepEqual((await call("/directory/create_user", { user: user({ external_id: undefined }) })).body, {
    external_id: "ext-alice@example.com",
  });
  assert.equal((await call("/directory/update_user", { user: user() })).status, 204);
  assert.equal((await call("/directory/delete_user", { user: user() })).status, 204);
  assert.equal((await call("/directory/set_password", { user: user(), password: "pw" })).status, 204);
  assert.equal((await call("/directory/verify_password", { user: user(), password: "pw" })).status, 204);
});

test("errors carry protocol codes", async () => {
  const cases: [string, unknown, number, string | undefined][] = [
    ["/directory/update_user", { user: user({ external_id: "missing" }) }, 404, "not_found"],
    ["/directory/set_password", { user: user({ email: "bob@sso.example" }), password: "x" }, 501, "unsupported"],
    ["/directory/verify_password", { user: user(), password: "wrong" }, 403, "invalid_credentials"],
    ["/directory/send_invitation", { user: user() }, 501, "unsupported"],
    ["/directory/create_user", { user: user({ email: "empty@example.com" }) }, 500, undefined],
    ["/directory/explode", { user: user() }, 404, undefined],
    ["/mailer/send", { to: ["a@b.c"], subject: "boom", text: "" }, 500, undefined],
  ];
  for (const [path, body, status, code] of cases) {
    const res = await call(path, body);
    assert.equal(res.status, status, path);
    assert.equal(res.body.code, code, path);
    assert.ok(res.body.error, path);
  }
});

test("mailer sends", async () => {
  const msg: Message = { to: ["a@b.c"], subject: "Welcome", text: "hi", tag: "invitation" };
  assert.equal((await call("/mailer/send", msg)).status, 204);
  assert.deepEqual(outbox.at(-1), msg);
});

test("wrong secret is refused", async () => {
  assert.equal((await call("/mailer/send", { to: ["a@b.c"] }, "nope")).status, 401);
});
