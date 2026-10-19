import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import {
  Client,
  TenariumError,
  TokenSource,
  collect,
  etagOf,
  isNotFound,
  isQuotaExceeded,
  isVersionConflict,
  responseOf,
  type StoredTokenPair,
  type Tenant,
} from "../src/index.ts";

// --- stub server ---------------------------------------------------------------------

interface Recorded {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: IncomingMessage["headers"];
  body: string;
}

type Handler = (req: Recorded, res: ServerResponse) => void | Promise<void>;

let server: Server;
let baseUrl: string;
let requests: Recorded[] = [];
let handler: Handler = (_req, res) => json(res, 404, { error: { code: "not_found", message: "no handler" } });

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

before(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const u = new URL(req.url ?? "/", "http://stub");
      const r: Recorded = {
        method: req.method ?? "",
        path: u.pathname,
        query: u.searchParams,
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      requests.push(r);
      Promise.resolve(handler(r, res)).catch((err) => {
        res.writeHead(500);
        res.end(String(err));
      });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((r) => server.close(() => r())));

beforeEach(() => {
  requests = [];
});

const acme: Tenant = {
  id: "11111111-1111-1111-1111-111111111111", slug: "acme", name: "Acme", status: "active",
  version: 3, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z",
};

// --- tests ---------------------------------------------------------------------------

test("sends credentials, encodes path and query, decodes typed results with metadata", async () => {
  handler = (r, res) => json(res, 200, { items: [acme] }, { ETag: '"3"', "X-Request-ID": "req-1" });
  const c = new Client({ baseUrl: baseUrl + "/", apiKey: "tnr_secret" });
  const page = await c.listTenants({ status: "active", label: ["tier=gold", "region=eu"], include_deleted: false, limit: 10 });
  assert.equal(page.items[0].slug, "acme");
  assert.deepEqual(Object.keys(page), ["items"], "metadata is not enumerable");
  assert.equal(etagOf(page), '"3"');
  assert.equal(responseOf(page)?.requestId, "req-1");
  assert.equal(responseOf(page)?.status, 200);

  const r = requests[0];
  assert.equal(r.method, "GET");
  assert.equal(r.path, "/v1/tenants");
  assert.equal(r.headers.authorization, "Bearer tnr_secret");
  assert.equal(r.query.get("status"), "active");
  assert.deepEqual(r.query.getAll("label"), ["tier=gold", "region=eu"]);
  assert.equal(r.query.get("include_deleted"), "false");
  assert.equal(r.query.get("limit"), "10");
  assert.equal(r.query.has("plan"), false);

  await c.getMember("a/b", "m 1").catch(() => {});
  assert.equal(requests[1].path, "/v1/tenants/a%2Fb/members/m%201");
  await assert.rejects(() => c.getTenant(""), /empty path parameter id/);
});

test("ifMatch accepts versions and ETags; PATCH is never retried", async () => {
  handler = (_r, res) => json(res, 503, { error: { code: "unavailable", message: "busy" } });
  const c = new Client({ baseUrl, token: "t", maxRetries: 3, retryBackoffMs: 1 });
  await assert.rejects(() => c.updateTenant("acme", { plan: "pro" }, { ifMatch: 3 }), (e: unknown) => e instanceof TenariumError && e.status === 503);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].headers["if-match"], '"3"');
  assert.equal(requests[0].headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(requests[0].body), { plan: "pro" });

  handler = (_r, res) => json(res, 412, { error: { code: "version_conflict", message: "changed" } });
  const err = await c.updatePlan("pro", { name: "Pro" }, { ifMatch: '"7"' }).catch((e: unknown) => e);
  assert.ok(isVersionConflict(err));
  assert.equal(requests[1].headers["if-match"], '"7"');
});

test("create calls get an automatic Idempotency-Key that is reused across retries", async () => {
  let n = 0;
  handler = (_r, res) => (++n < 3 ? json(res, 503, { error: { code: "unavailable", message: "x" } }) : json(res, 201, acme));
  const c = new Client({ baseUrl, apiKey: "k", maxRetries: 3, retryBackoffMs: 1 });
  const t = await c.createTenant({ slug: "acme", name: "Acme" });
  assert.equal(t.slug, "acme");
  assert.equal(requests.length, 3);
  const key = requests[0].headers["idempotency-key"];
  assert.ok(typeof key === "string" && key.length >= 16);
  assert.ok(requests.every((r) => r.headers["idempotency-key"] === key));

  // Without retries there is no automatic key, and a POST is not retried.
  requests = [];
  n = 0;
  const once = new Client({ baseUrl, apiKey: "k" });
  await assert.rejects(() => once.createTenant({ slug: "acme", name: "Acme" }));
  assert.equal(requests.length, 1);
  assert.equal(requests[0].headers["idempotency-key"], undefined);

  // A non-create POST is retried only with an explicit key.
  requests = [];
  n = 0;
  await assert.rejects(() => c.suspendTenant("acme", { reason: "x" }));
  assert.equal(requests.length, 1);
  requests = [];
  n = 0;
  await c.suspendTenant("acme", { reason: "x" }, { idempotencyKey: "fixed" });
  assert.equal(requests.length, 3);
  assert.ok(requests.every((r) => r.headers["idempotency-key"] === "fixed"));
});

test("429 is retried only with Retry-After; errors carry code, field and request ID", async () => {
  let n = 0;
  handler = (_r, res) =>
    ++n === 1
      ? json(res, 429, { error: { code: "rate_limited", message: "slow down" } }, { "Retry-After": "1" })
      : json(res, 200, { metric: "api_calls", value: 1 });
  const c = new Client({ baseUrl, apiKey: "k", maxRetries: 2, retryBackoffMs: 1 });
  const start = Date.now();
  const item = await c.recordUsage("acme", "api_calls", { delta: 1 });
  assert.equal(item.value, 1);
  assert.ok(Date.now() - start >= 900, "waited for Retry-After");
  assert.equal(requests.length, 2);
  assert.ok(requests[0].headers["idempotency-key"], "recordUsage gets an automatic key");

  requests = [];
  handler = (_r, res) =>
    json(res, 429, { error: { code: "quota_exceeded", message: "limit reached", field: "api_calls" } }, { "X-Request-ID": "r-9" });
  const err = await c.recordUsage("acme", "api_calls", { delta: 1 }).catch((e: unknown) => e);
  assert.equal(requests.length, 1);
  assert.ok(isQuotaExceeded(err));
  assert.ok(err instanceof TenariumError);
  assert.equal(err.status, 429);
  assert.equal(err.code, "quota_exceeded");
  assert.equal(err.message, "limit reached");
  assert.equal(err.field, "api_calls");
  assert.equal(err.requestId, "r-9");
  assert.match(String(err), /429 quota_exceeded: limit reached \(field api_calls\) \[request r-9\]/);
});

test("network errors and 502/504 are retried for GET", async () => {
  let n = 0;
  handler = (_r, res) => {
    n++;
    if (n === 1) return void res.socket?.destroy();
    if (n === 2) return json(res, 504, {});
    json(res, 200, acme);
  };
  const c = new Client({ baseUrl, apiKey: "k", maxRetries: 2, retryBackoffMs: 1 });
  const t = await c.getTenant("acme");
  assert.equal(t.id, acme.id);
  assert.equal(n, 3);
});

test("non-JSON and SCIM errors", async () => {
  handler = (_r, res) => {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end("bad gateway");
  };
  const c = new Client({ baseUrl, apiKey: "k" });
  const e1 = await c.getTenant("acme").catch((e: unknown) => e);
  assert.ok(e1 instanceof TenariumError);
  assert.equal(e1.code, "");
  assert.equal(e1.message, "bad gateway");

  handler = (_r, res) => json(res, 404, { schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "404", detail: "no such user" });
  const e2 = await c.scimGetUser("acme", "u1").catch((e: unknown) => e);
  assert.ok(isNotFound(e2));
  assert.equal(e2.message, "no such user");
});

test("paginates with after cursors and with before cursors", async () => {
  handler = (r, res) => {
    const after = r.query.get("after");
    if (r.path === "/v1/tenants") {
      if (!after) return json(res, 200, { items: [{ ...acme, slug: "a" }, { ...acme, slug: "b" }], next: "c2" });
      if (after === "c2") return json(res, 200, { items: [{ ...acme, slug: "c" }], next: "c3" });
      return json(res, 200, { items: [] });
    }
    // /v1/tenants/acme/audit: newest first, next is passed as before.
    const before = r.query.get("before");
    if (!before) return json(res, 200, { items: [{ seq: 9 }, { seq: 8 }], next: "8" });
    return json(res, 200, { items: [{ seq: 7 }] });
  };
  const c = new Client({ baseUrl, apiKey: "k" });
  const slugs: string[] = [];
  for await (const t of c.listTenantsAll({ status: "active", limit: 2 })) slugs.push(t.slug);
  assert.deepEqual(slugs, ["a", "b", "c"]);
  assert.deepEqual(requests.map((r) => r.query.get("after")), [null, "c2", "c3"]);
  assert.ok(requests.every((r) => r.query.get("status") === "active" && r.query.get("limit") === "2"));

  requests = [];
  const events = await collect(c.listTenantAuditAll("acme", { type: ["tenant.*"] }));
  assert.deepEqual(events.map((e) => e.seq), [9, 8, 7]);
  assert.deepEqual(requests.map((r) => r.query.get("before")), [null, "8"]);
  assert.deepEqual(requests[1].query.getAll("type"), ["tenant.*"]);

  requests = [];
  assert.equal((await collect(c.listTenantsAll(), 1)).length, 1);
  assert.equal(requests.length, 1, "stops fetching when the consumer stops");
});

test("public operations send no credentials", async () => {
  handler = (_r, res) => json(res, 200, { access_token: "a", token_type: "Bearer", expires_in: 900, refresh_token: "r" });
  const c = new Client({ baseUrl, apiKey: "k" });
  const pair = await c.token({ grant_type: "password", email: "a@b.c", password: "pw" });
  assert.equal(pair.access_token, "a");
  assert.equal(requests[0].headers.authorization, undefined);
});

test("token source refreshes before expiry, once on 401, and serializes refreshes", async () => {
  let refreshes = 0;
  let valid = "";
  handler = async (r, res) => {
    if (r.path === "/v1/auth/token") {
      const body = JSON.parse(r.body);
      assert.equal(body.grant_type, "refresh_token");
      assert.equal(body.refresh_token, `r${refreshes}`, "uses the latest rotated refresh token");
      refreshes++;
      await new Promise((ok) => setTimeout(ok, 20));
      valid = `a${refreshes}`;
      return json(res, 200, { access_token: valid, token_type: "Bearer", expires_in: 900, refresh_token: `r${refreshes}` });
    }
    if (r.headers.authorization !== `Bearer ${valid}`) return json(res, 401, { error: { code: "unauthorized", message: "bad token" } });
    json(res, 200, acme);
  };
  const saved: StoredTokenPair[] = [];
  let now = 1_000_000;
  const pub = new Client({ baseUrl });
  // Expired pair: the first call refreshes before sending.
  const ts = new TokenSource(pub, { access_token: "a0", token_type: "Bearer", expires_in: 60, refresh_token: "r0" }, {
    now: () => now,
    onRefresh: (p) => void saved.push(p),
  });
  now += 59_000;
  const c = pub.with({ tokenSource: ts });

  const results = await Promise.all([c.getTenant("acme"), c.getTenant("acme"), c.getTenant("acme")]);
  assert.equal(results.length, 3);
  assert.equal(refreshes, 1, "concurrent callers share one refresh");
  assert.equal(saved.length, 1);
  assert.equal(saved[0].refresh_token, "r1");
  assert.equal(saved[0].expires_at, now + 900_000);

  // The server revokes the access token: one refresh and retry.
  valid = "something-else";
  requests = [];
  await c.getTenant("acme");
  assert.equal(refreshes, 2);
  assert.deepEqual(requests.map((r) => r.path), ["/v1/tenants/acme", "/v1/auth/token", "/v1/tenants/acme"]);

  // A request that still fails after the refresh reports the 401.
  handler = (_r, res) =>
    _r.path === "/v1/auth/token"
      ? json(res, 200, { access_token: "x", token_type: "Bearer", expires_in: 900, refresh_token: "y" })
      : json(res, 401, { error: { code: "unauthorized", message: "no" } });
  const err = await c.getTenant("acme").catch((e: unknown) => e);
  assert.ok(err instanceof TenariumError && err.status === 401);
});

test("timeouts and aborts", async () => {
  handler = (_r, res) => void setTimeout(() => json(res, 200, acme), 300);
  const c = new Client({ baseUrl, apiKey: "k", timeoutMs: 50 });
  await assert.rejects(() => c.getTenant("acme"), /timed out after 50ms/);

  const ctrl = new AbortController();
  const p = new Client({ baseUrl, apiKey: "k" }).getTenant("acme", { signal: ctrl.signal });
  setTimeout(() => ctrl.abort(new Error("stop")), 20);
  await assert.rejects(() => p, /stop/);
});

test("form bodies, text responses, empty responses and raw calls", async () => {
  handler = (r, res) => {
    if (r.path.endsWith("/metadata")) {
      res.writeHead(200, { "Content-Type": "application/samlmetadata+xml" });
      return void res.end("<EntityDescriptor/>");
    }
    if (r.path === "/readyz") return json(res, 200, { status: "ok" });
    res.writeHead(204);
    res.end();
  };
  const c = new Client({ baseUrl, apiKey: "k" });
  assert.equal(await c.samlMetadata("t1"), "<EntityDescriptor/>");
  await c.samlACS("t1", { SAMLResponse: "PHNhbWw+", RelayState: "s" }, { headers: { "X-Test": "1" } }).catch(() => {});
  const acs = requests[1];
  assert.equal(acs.headers["content-type"], "application/x-www-form-urlencoded");
  assert.equal(acs.body, "SAMLResponse=PHNhbWw%2B&RelayState=s");
  assert.equal(acs.headers.authorization, undefined);
  assert.equal(acs.headers["x-test"], "1");
  assert.equal(await c.deletePlan("pro"), undefined);
  assert.deepEqual(await c.call("GET", "/readyz"), { status: "ok" });
});

test("rejects invalid base URLs and derives clients with other credentials", () => {
  assert.throws(() => new Client({ baseUrl: "localhost:8080" }), /invalid base URL/);
  assert.throws(() => new Client({ baseUrl: "ftp://x" }), /invalid base URL/);
  const c = new Client({ baseUrl, apiKey: "k" });
  const d = c.with({ token: "t" });
  assert.equal(d.baseUrl, baseUrl);
});
