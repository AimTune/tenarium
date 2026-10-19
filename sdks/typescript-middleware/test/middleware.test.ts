import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import type { AddressInfo } from "node:net";

import {
  Client,
  QuotaExceededError,
  Resolver,
  TenantError,
  UsageRecorder,
  Verifier,
  apiSource,
  cachingDomains,
  cachingSource,
  checkClaims,
  fromCustomDomain,
  fromHeader,
  fromPathPrefix,
  fromSubdomain,
  fromToken,
  hasFeature,
  limitOf,
  redisSource,
  requireFeature,
  resolveTenant,
  tenantMiddleware,
  tenantOf,
  withTenant,
  type Source,
  type Tenant,
  type TenantStatus,
} from "../src/index.ts";

const ISSUER = "https://tenarium.test";
const acme: Tenant = { id: "id-acme", slug: "acme", status: "active", plan: "pro", features: { sso: true }, limits: { seats: 10 } };
const globex: Tenant = { id: "id-globex", slug: "globex", status: "active", features: {}, limits: {} };
const frozen: Tenant = { id: "id-frozen", slug: "frozen", status: "suspended", features: {}, limits: {} };

function memorySource(...tenants: Tenant[]): Source & { calls: number } {
  const s = {
    calls: 0,
    async get(ref: string) {
      s.calls++;
      return tenants.find((t) => t.id === ref || t.slug === ref) ?? null;
    },
  };
  return s;
}

function req(host: string, path = "/", headers: Record<string, string> = {}) {
  const h: Record<string, string> = { host };
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = v;
  return { url: path, headers: h };
}

async function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{ url: string; server: Server }> {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

// --- A real ES256 issuer with a JWKS endpoint --------------------------------

const keys: { kid: string; priv: KeyObject; pub: KeyObject }[] = [];
let jwksFetches = 0;
let jwks: { url: string; server: Server };

function rotate() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  keys.push({ kid: `k${keys.length}`, priv: privateKey, pub: publicKey });
}

function signToken(claims: Record<string, unknown>, kid = keys.at(-1)!.kid): string {
  const key = keys.find((k) => k.kid === kid)!;
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  const input = `${enc({ alg: "ES256", typ: "at+jwt", kid })}.${enc({
    iss: ISSUER, sub: "user-1", aud: ["tenarium"], iat: now, nbf: now, exp: now + 60, roles: ["viewer"], ...claims,
  })}`;
  const sig = sign("sha256", Buffer.from(input), { key: key.priv, dsaEncoding: "ieee-p1363" });
  return `${input}.${sig.toString("base64url")}`;
}

before(async () => {
  rotate();
  jwks = await listen((_req, res) => {
    jwksFetches++;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({
      keys: keys.map((k) => ({ ...k.pub.export({ format: "jwk" }), kid: k.kid, use: "sig", alg: "ES256" })),
    }));
  });
});
after(() => jwks.server.close());

// --- Tests ---------------------------------------------------------------------

test("resolvers", async () => {
  const source = memorySource(acme, globex);
  const cases: [string, Resolver, ReturnType<typeof req>, string | null][] = [
    ["subdomain", new Resolver(fromSubdomain("app.example.com")), req("acme.app.example.com:8443"), "acme"],
    ["subdomain case", new Resolver(fromSubdomain("App.Example.com")), req("ACME.app.example.com."), "acme"],
    ["subdomain base", new Resolver(fromSubdomain("app.example.com")), req("app.example.com"), null],
    ["subdomain nested", new Resolver(fromSubdomain("app.example.com")), req("x.acme.app.example.com"), null],
    ["header slug", new Resolver(fromHeader("X-Tenant-ID")), req("h", "/", { "X-Tenant-ID": "globex" }), "globex"],
    ["header id", new Resolver(fromHeader("X-Tenant-ID")), req("h", "/", { "X-Tenant-ID": "id-acme" }), "acme"],
    ["path", new Resolver(fromPathPrefix()), req("h", "/t/acme/projects?x=1"), "acme"],
    ["path other", new Resolver(fromPathPrefix()), req("h", "/api/acme"), null],
  ];
  for (const [name, resolver, r, want] of cases) {
    if (want === null) {
      await assert.rejects(resolveTenant(r, { resolver, source }), (e: TenantError) => e.status === 404, name);
    } else {
      const ctx = await resolveTenant(r, { resolver, source });
      assert.equal(ctx.tenant?.slug, want, name);
    }
  }
  // fetch Request objects work too.
  const ctx = await resolveTenant(new Request("http://globex.app.example.com/x"), {
    resolver: new Resolver(fromSubdomain("app.example.com")), source,
  });
  assert.equal(ctx.tenant?.slug, "globex");
});

test("precedence: first match wins, later sources skipped", async () => {
  const source = memorySource(acme, globex);
  const r = req("acme.app.example.com", "/t/globex", { "x-tenant": "globex" });
  let headerFirst = await resolveTenant(r, { resolver: new Resolver(fromHeader("x-tenant"), fromSubdomain("app.example.com")), source });
  assert.equal(headerFirst.tenant?.slug, "globex");
  const subFirst = await resolveTenant(r, { resolver: new Resolver(fromSubdomain("app.example.com"), fromPathPrefix()), source });
  assert.equal(subFirst.tenant?.slug, "acme");

  let calls = 0;
  const spy = { name: "spy", extract() { calls++; return null; } };
  await new Resolver(fromSubdomain("app.example.com"), spy).resolve(r);
  assert.equal(calls, 0);
  headerFirst = await resolveTenant(req("acme.app.example.com"), { resolver: new Resolver(spy, fromSubdomain("app.example.com")), source });
  assert.equal(calls, 1);
});

test("status, optional, deleted and source failure", async () => {
  const resolver = new Resolver(fromHeader("x-tenant"));
  const source = memorySource(acme, frozen, { ...globex, slug: "gone", status: "deleted" });
  await assert.rejects(resolveTenant(req("h", "/", { "x-tenant": "frozen" }), { resolver, source }),
    (e: TenantError) => e.status === 403 && e.code === "tenant_inactive");
  await assert.rejects(resolveTenant(req("h", "/", { "x-tenant": "gone" }), { resolver, source }),
    (e: TenantError) => e.status === 404);
  await assert.rejects(resolveTenant(req("h"), { resolver, source }), (e: TenantError) => e.code === "tenant_required");
  const lenient = { resolver, source, optional: true, allowedStatuses: ["active", "suspended"] as TenantStatus[] };
  assert.equal((await resolveTenant(req("h", "/", { "x-tenant": "frozen" }), lenient)).tenant?.slug, "frozen");
  assert.equal((await resolveTenant(req("h"), lenient)).tenant, null);

  const broken: Source = { get: async () => { throw new Error("redis down: secret"); } };
  await assert.rejects(resolveTenant(req("h", "/", { "x-tenant": "acme" }), { resolver, source: broken }), (e: TenantError) => {
    assert.equal(e.status, 503);
    assert.doesNotMatch(JSON.stringify(e.toJSON()), /secret/);
    return true;
  });
});

test("real ES256 token: verification, tid, mismatch, rejection", async () => {
  const verifier = new Verifier({ jwksUrl: jwks.url, issuer: ISSUER });
  const source = memorySource(acme, globex);
  const tok = signToken({ tid: "id-acme", email: "ada@example.com" });

  for (const tokenFirst of [true, false]) {
    const ex = [fromToken(verifier), fromSubdomain("app.example.com")];
    const resolver = new Resolver(...(tokenFirst ? ex : ex.reverse()));
    const opts = { resolver, source };
    const auth = { authorization: `Bearer ${tok}` };

    const ctx = await resolveTenant(req("localhost", "/", auth), opts);
    assert.equal(ctx.tenant?.id, "id-acme");
    assert.equal(ctx.claims?.email, "ada@example.com");
    assert.equal((await resolveTenant(req("acme.app.example.com", "/", auth), opts)).tenant?.slug, "acme");
    await assert.rejects(resolveTenant(req("globex.app.example.com", "/", auth), opts),
      (e: TenantError) => e.status === 403 && e.code === "tenant_mismatch");
  }

  const resolver = new Resolver(fromToken(verifier), fromHeader("x-tenant"));
  const now = Math.floor(Date.now() / 1000);
  const bad: [string, string, number][] = [
    ["expired", signToken({ tid: "id-acme", exp: now - 3600 }), 401],
    ["audience", signToken({ tid: "id-acme", aud: "other" }), 401],
    ["tampered", tok.replace(/\.[^.]+\./, "." + Buffer.from(JSON.stringify({ iss: ISSUER, tid: "id-globex", aud: "tenarium", exp: now + 60 })).toString("base64url") + "."), 401],
    ["foreign issuer ignored", signToken({ tid: "id-acme", iss: "https://other" }), 200],
    ["api key ignored", "tnm_live_key", 200],
  ];
  for (const [name, t, status] of bad) {
    const p = resolveTenant(req("h", "/", { authorization: `Bearer ${t}`, "x-tenant": "globex" }), { resolver, source });
    if (status === 200) assert.equal((await p).tenant?.slug, "globex", name);
    else await assert.rejects(p, (e: TenantError) => e.status === status, name);
  }
});

test("verifier caches keys and refreshes on unknown kid", async () => {
  const verifier = new Verifier({ jwksUrl: jwks.url, issuer: ISSUER, minRefreshIntervalMs: 0 });
  const start = jwksFetches;
  await verifier.verify(signToken({ tid: "a" }));
  await verifier.verify(signToken({ tid: "a" }));
  assert.equal(jwksFetches - start, 1);
  rotate();
  const c = await verifier.verify(signToken({ tid: "b" }));
  assert.equal(c.tid, "b");
  assert.equal(jwksFetches - start, 2);

  const slow = new Verifier({ jwksUrl: jwks.url, issuer: ISSUER, minRefreshIntervalMs: 3_600_000 });
  await slow.verify(signToken({ tid: "a" }));
  const n = jwksFetches;
  rotate();
  await assert.rejects(slow.verify(signToken({ tid: "a" })), /unknown signing key/);
  assert.equal(jwksFetches, n);

  assert.throws(() => checkClaims({ iss: ISSUER, sub: "s", aud: "tenarium", exp: 1 }, { issuer: ISSUER }), /expired/);
});

test("caching source: hits, negative cache, dedup, errors", async () => {
  const src = memorySource(acme);
  const cached = cachingSource(src, 60_000);
  for (let i = 0; i < 5; i++) assert.equal((await cached.get("acme"))?.id, "id-acme");
  assert.equal(src.calls, 1);
  for (let i = 0; i < 5; i++) assert.equal(await cached.get("ghost"), null);
  assert.equal(src.calls, 2);
  cached.invalidate("acme");
  await cached.get("acme");
  assert.equal(src.calls, 3);

  const noNeg = cachingSource(src, 60_000, { negativeTtlMs: 0 });
  await noNeg.get("ghost");
  await noNeg.get("ghost");
  assert.equal(src.calls, 5);

  let slowCalls = 0;
  const slow = cachingSource({ get: async () => { slowCalls++; await new Promise((r) => setTimeout(r, 30)); return acme; } }, 60_000);
  const all = await Promise.all(Array.from({ length: 20 }, () => slow.get("acme")));
  assert.ok(all.every((t) => t?.id === "id-acme"));
  assert.equal(slowCalls, 1);

  let failures = 0;
  const flaky = cachingSource({ get: async () => { failures++; throw new Error("boom"); } }, 60_000);
  await assert.rejects(flaky.get("x"));
  await assert.rejects(flaky.get("x"));
  assert.equal(failures, 2);
});

test("redis source reads the plugin's key format", async () => {
  const store = new Map<string, string>([
    ["tenarium:tenant:id-acme", JSON.stringify({ ...acme, name: "Acme", version: 3, updated_at: "2026-01-01T00:00:00Z" })],
    ["tenarium:tenant-slug:acme", "id-acme"],
  ]);
  const src = redisSource({ get: async (k) => store.get(k) ?? null });
  assert.equal((await src.get("id-acme"))?.slug, "acme");
  const bySlug = await src.get("acme");
  assert.equal(bySlug?.id, "id-acme");
  assert.ok(hasFeature(bySlug, "sso"));
  assert.equal(limitOf(bySlug, "seats"), 10);
  assert.equal(limitOf(bySlug, "storage"), undefined);
  assert.equal(await src.get("ghost"), null);
});

test("API source, custom domains and usage against a stub API", async () => {
  const seen: string[] = [];
  let used = 0;
  const api = await listen((r, res) => {
    seen.push(`${r.method} ${r.url}`);
    res.setHeader("content-type", "application/json");
    if (r.headers.authorization !== "Bearer key") { res.statusCode = 401; return res.end("{}"); }
    const url = new URL(r.url!, "http://x");
    const notFound = () => { res.statusCode = 404; res.end(JSON.stringify({ error: { code: "not_found", message: "nope" } })); };
    if (url.pathname === "/v1/tenants/acme" || url.pathname === "/v1/tenants/id-acme") {
      return res.end(JSON.stringify({ id: "id-acme", slug: "acme", name: "Acme", status: "active", plan: "pro", features: { beta: true }, version: 1 }));
    }
    if (url.pathname === "/v1/tenants/id-acme/entitlements") {
      return res.end(JSON.stringify({ tenant_id: "id-acme", plan: "pro", features: { sso: true }, limits: { api_calls: 2 } }));
    }
    if (url.pathname === "/v1/domains/resolve") {
      if (url.searchParams.get("host") === "shop.acme.com") return res.end(JSON.stringify({ tenant_id: "id-acme", slug: "acme", hostname: "shop.acme.com" }));
      return notFound();
    }
    if (r.method === "POST" && url.pathname === "/v1/tenants/id-acme/usage/api_calls") {
      if (used >= 2) { res.statusCode = 429; return res.end(JSON.stringify({ error: { code: "quota_exceeded", message: "limit reached" } })); }
      return res.end(JSON.stringify({ metric: "api_calls", value: ++used, limit: 2 }));
    }
    notFound();
  });
  try {
    const t = await apiSource(api.url, "key").get("acme");
    assert.deepEqual([t?.id, t?.features, t?.limits], ["id-acme", { sso: true }, { api_calls: 2 }]);
    assert.equal(await apiSource(api.url, "key").get("ghost"), null);

    const client = new Client(api.url, "key");
    const resolver = new Resolver(fromSubdomain("app.example.com"), fromCustomDomain(cachingDomains(client, 60_000)));
    const source = cachingSource(client, 60_000);
    for (let i = 0; i < 3; i++) {
      assert.equal((await resolveTenant(req("shop.acme.com"), { resolver, source })).tenant?.id, "id-acme");
      await assert.rejects(resolveTenant(req("unknown.org"), { resolver, source }), (e: TenantError) => e.status === 404);
    }
    assert.equal(seen.filter((s) => s.includes("/v1/domains/resolve")).length, 2);

    const usage = new UsageRecorder(client);
    assert.equal((await usage.record("id-acme", "api_calls")).value, 1);
    assert.equal((await usage.record("id-acme", "api_calls")).value, 2);
    await assert.rejects(usage.record("id-acme", "api_calls"), (e: unknown) => e instanceof QuotaExceededError && e.status === 429);
  } finally {
    api.server.close();
  }
});

test("express-style middleware, requireFeature and node:http wrapper", async () => {
  const opts = { resolver: new Resolver(fromHeader("x-tenant")), source: memorySource(acme, globex, frozen) };
  const mw = tenantMiddleware(opts);
  const feature = requireFeature("sso");

  // A tiny connect-style chain on a real server.
  const app = await listen((rq, rs) => {
    mw(rq, rs, () => feature(rq, rs, () => rs.end(`hello ${tenantOf(rq)?.slug}`)));
  });
  const plain = await listen(withTenant(opts, (_rq, rs, ctx) => { rs.end(`plain ${ctx.tenant?.slug}`); }));
  try {
    const get = async (base: string, tenant?: string) => {
      const r = await fetch(base, { headers: tenant ? { "x-tenant": tenant } : {} });
      return [r.status, await r.text()] as const;
    };
    assert.deepEqual(await get(app.url, "acme"), [200, "hello acme"]);
    const [code, body] = await get(app.url, "globex");
    assert.equal(code, 403);
    assert.equal(JSON.parse(body).error.code, "feature_disabled");
    assert.equal((await get(app.url, "frozen"))[0], 403);
    assert.equal((await get(app.url, "ghost"))[0], 404);
    assert.equal((await get(app.url))[0], 404);

    assert.deepEqual(await get(plain.url, "globex"), [200, "plain globex"]);
    assert.equal((await get(plain.url, "frozen"))[0], 403);
  } finally {
    app.server.close();
    plain.server.close();
  }
});
