import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from tenarium_middleware import (  # noqa: E402
    ApiClient,
    CachingDomains,
    CachingSource,
    Extractor,
    InvalidToken,
    QuotaExceeded,
    Request,
    Resolver,
    Tenant,
    TenantASGIMiddleware,
    TenantError,
    TenantMiddleware,
    TokenVerifier,
    UsageRecorder,
    api_source,
    check_claims,
    current_tenant,
    from_custom_domain,
    from_header,
    from_path_prefix,
    from_subdomain,
    from_token,
    redis_source,
    require_feature,
    resolve_tenant,
)

ISSUER = "https://tenarium.test"
ACME = Tenant(id="id-acme", slug="acme", status="active", plan="pro", features={"sso": True}, limits={"seats": 10})
GLOBEX = Tenant(id="id-globex", slug="globex", status="active")
FROZEN = Tenant(id="id-frozen", slug="frozen", status="suspended")
GONE = Tenant(id="id-gone", slug="gone", status="deleted")


class MemorySource:
    def __init__(self, *tenants, delay=0.0):
        self.tenants = tenants
        self.calls = 0
        self.delay = delay
        self._lock = threading.Lock()

    def get(self, ref):
        with self._lock:
            self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        return next((t for t in self.tenants if ref in (t.id, t.slug)), None)


def req(host, path="/", **headers):
    return Request(host=host, path=path, headers={k.replace("_", "-").lower(): v for k, v in headers.items()})


# Stand-in for PyJWT: HS256 tokens checked with hmac (the stdlib has no ECDSA).
SECRET = b"test-secret"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(**claims):
    now = int(time.time())
    payload = {"iss": ISSUER, "sub": "user-1", "aud": ["tenarium"], "iat": now, "nbf": now, "exp": now + 60}
    payload.update(claims)
    signing_input = b64(json.dumps({"alg": "HS256", "kid": "k0"}).encode()) + "." + b64(json.dumps(payload).encode())
    sig = hmac.new(SECRET, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64(sig)


def hmac_decode(token):
    head, payload, sig = token.split(".")
    want = hmac.new(SECRET, (head + "." + payload).encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(b64(want), sig):
        raise ValueError("signature verification failed")
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


VERIFIER = TokenVerifier(ISSUER, hmac_decode)


class ResolverTests(unittest.TestCase):
    def test_sources(self):
        src = MemorySource(ACME, GLOBEX)
        cases = [
            ("subdomain", from_subdomain("app.example.com"), Request.from_wsgi({"HTTP_HOST": "ACME.app.example.com:8443"}), "acme"),
            ("subdomain base", from_subdomain("app.example.com"), req("app.example.com"), None),
            ("subdomain nested", from_subdomain("app.example.com"), req("x.acme.app.example.com"), None),
            ("header slug", from_header("X-Tenant-ID"), req("h", x_tenant_id="globex"), "globex"),
            ("header id", from_header("X-Tenant-ID"), Request.from_wsgi({"HTTP_X_TENANT_ID": "id-acme"}), "acme"),
            ("path", from_path_prefix(), req("h", "/t/acme/projects"), "acme"),
            ("path other", from_path_prefix(), req("h", "/api/acme"), None),
            ("unknown", from_header("X-Tenant"), req("h", x_tenant="nope"), None),
        ]
        for name, ex, r, want in cases:
            with self.subTest(name):
                if want is None:
                    with self.assertRaises(TenantError) as cm:
                        resolve_tenant(r, Resolver(ex), src)
                    self.assertEqual(cm.exception.status, 404)
                else:
                    self.assertEqual(resolve_tenant(r, Resolver(ex), src).tenant.slug, want)

    def test_asgi_request(self):
        r = Request.from_asgi({"type": "http", "path": "/t/x", "headers": [(b"host", b"Acme.App.Example.com.")]})
        self.assertEqual((r.host, r.path), ("acme.app.example.com", "/t/x"))

    def test_precedence(self):
        src = MemorySource(ACME, GLOBEX)
        r = req("acme.app.example.com", "/t/globex", x_tenant="globex")
        self.assertEqual(resolve_tenant(r, Resolver(from_header("x-tenant"), from_subdomain("app.example.com")), src).tenant.slug, "globex")
        self.assertEqual(resolve_tenant(r, Resolver(from_subdomain("app.example.com"), from_path_prefix()), src).tenant.slug, "acme")

        calls = []

        class Spy(Extractor):
            def extract(self, _req):
                calls.append(1)
                return None

        Resolver(from_subdomain("app.example.com"), Spy()).resolve(r)
        self.assertEqual(calls, [])


class StatusTests(unittest.TestCase):
    def test_status_optional_deleted_failure(self):
        src = MemorySource(ACME, FROZEN, GONE)
        res = Resolver(from_header("x-tenant"))
        for ref, status, code in [("frozen", 403, "tenant_inactive"), ("gone", 404, "tenant_not_found")]:
            with self.assertRaises(TenantError) as cm:
                resolve_tenant(req("h", x_tenant=ref), res, src)
            self.assertEqual((cm.exception.status, cm.exception.code), (status, code))
        with self.assertRaises(TenantError) as cm:
            resolve_tenant(req("h"), res, src)
        self.assertEqual(cm.exception.code, "tenant_required")

        lenient = dict(allowed_statuses=("active", "suspended"), optional=True)
        self.assertEqual(resolve_tenant(req("h", x_tenant="frozen"), res, src, **lenient).tenant.slug, "frozen")
        self.assertIsNone(resolve_tenant(req("h"), res, src, **lenient).tenant)

        class Broken:
            def get(self, ref):
                raise ConnectionError("redis down: secret")

        with self.assertRaises(TenantError) as cm:
            resolve_tenant(req("h", x_tenant="acme"), res, Broken())
        self.assertEqual(cm.exception.status, 503)
        self.assertNotIn("secret", json.dumps(cm.exception.body()))

    def test_tenant_helpers(self):
        self.assertTrue(ACME.has_feature("sso"))
        self.assertFalse(ACME.has_feature("beta"))
        self.assertEqual(ACME.limit("seats"), 10)
        self.assertIsNone(ACME.limit("storage"))


class TokenTests(unittest.TestCase):
    def test_token_resolution_and_mismatch(self):
        src = MemorySource(ACME, GLOBEX)
        tok = "Bearer " + make_token(tid="id-acme", email="ada@example.com")
        for token_first in (True, False):
            ex = [from_token(VERIFIER), from_subdomain("app.example.com")]
            resolver = Resolver(*(ex if token_first else ex[::-1]))
            with self.subTest(token_first=token_first):
                ctx = resolve_tenant(req("localhost", authorization=tok), resolver, src)
                self.assertEqual(ctx.tenant.id, "id-acme")
                self.assertEqual(ctx.claims["email"], "ada@example.com")
                self.assertEqual(resolve_tenant(req("acme.app.example.com", authorization=tok), resolver, src).tenant.slug, "acme")
                with self.assertRaises(TenantError) as cm:
                    resolve_tenant(req("globex.app.example.com", authorization=tok), resolver, src)
                self.assertEqual((cm.exception.status, cm.exception.code), (403, "tenant_mismatch"))

    def test_bad_and_foreign_tokens(self):
        src = MemorySource(ACME, GLOBEX)
        resolver = Resolver(from_token(VERIFIER), from_header("x-tenant"))
        good = make_token(tid="id-acme")
        head, _, sig = good.split(".")
        forged = head + "." + b64(json.dumps({"iss": ISSUER, "aud": "tenarium", "tid": "id-globex", "exp": time.time() + 60}).encode()) + "." + sig
        cases = [
            ("expired", make_token(tid="id-acme", exp=int(time.time()) - 3600), 401),
            ("audience", make_token(tid="id-acme", aud="other"), 401),
            ("bad signature", forged, 401),
            ("foreign issuer", make_token(tid="id-acme", iss="https://other"), 200),
            ("api key", "tnm_live_key", 200),
        ]
        for name, token, status in cases:
            with self.subTest(name):
                r = req("h", authorization="Bearer " + token, x_tenant="globex")
                if status == 200:
                    self.assertEqual(resolve_tenant(r, resolver, src).tenant.slug, "globex")
                else:
                    with self.assertRaises(TenantError) as cm:
                        resolve_tenant(r, resolver, src)
                    self.assertEqual(cm.exception.status, status)

    def test_check_claims(self):
        ok = {"iss": ISSUER, "aud": "tenarium", "exp": time.time() + 60}
        check_claims(ok, ISSUER)
        for bad in ({**ok, "iss": "x"}, {**ok, "aud": ["x"]}, {**ok, "exp": 1}, {**ok, "nbf": time.time() + 3600}, {"iss": ISSUER, "aud": "tenarium"}):
            with self.assertRaises(InvalidToken):
                check_claims(bad, ISSUER)


class CacheTests(unittest.TestCase):
    def test_hits_negative_and_errors(self):
        src = MemorySource(ACME)
        cache = CachingSource(src, ttl=60)
        for _ in range(5):
            self.assertEqual(cache.get("acme").id, "id-acme")
        self.assertEqual(src.calls, 1)
        for _ in range(5):
            self.assertIsNone(cache.get("ghost"))
        self.assertEqual(src.calls, 2)
        cache.invalidate("acme")
        cache.get("acme")
        self.assertEqual(src.calls, 3)

        no_neg = CachingSource(src, ttl=60, negative_ttl=0)
        no_neg.get("ghost")
        no_neg.get("ghost")
        self.assertEqual(src.calls, 5)

        class Flaky:
            calls = 0

            def get(self, ref):
                Flaky.calls += 1
                raise ConnectionError("boom")

        flaky = CachingSource(Flaky(), ttl=60)
        for _ in range(2):
            with self.assertRaises(ConnectionError):
                flaky.get("x")
        self.assertEqual(Flaky.calls, 2)

        short = CachingSource(MemorySource(ACME), ttl=0.01)
        short.get("acme")
        time.sleep(0.02)
        short.get("acme")
        self.assertEqual(short.source.calls, 2)

    def test_concurrent_misses_share_one_load(self):
        src = MemorySource(ACME, delay=0.05)
        cache = CachingSource(src, ttl=60)
        results = []
        threads = [threading.Thread(target=lambda: results.append(cache.get("acme"))) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 20)
        self.assertTrue(all(r.id == "id-acme" for r in results))
        self.assertEqual(src.calls, 1)


class FakeRedis:
    def __init__(self, data):
        self.data = data

    def get(self, key):
        v = self.data.get(key)
        return v.encode() if v is not None else None  # redis-py returns bytes


class RedisSourceTests(unittest.TestCase):
    def test_plugin_key_format(self):
        cached = {"id": "id-acme", "slug": "acme", "name": "Acme", "status": "active", "plan": "pro",
                  "labels": {"region": "eu"}, "features": {"sso": True}, "limits": {"seats": 5},
                  "version": 3, "updated_at": "2026-01-01T00:00:00Z"}
        src = redis_source(FakeRedis({"tenarium:tenant:id-acme": json.dumps(cached), "tenarium:tenant-slug:acme": "id-acme"}))
        for ref in ("id-acme", "acme"):
            t = src.get(ref)
            self.assertEqual((t.id, t.slug, t.plan, t.version, t.labels["region"]), ("id-acme", "acme", "pro", 3, "eu"))
            self.assertTrue(t.has_feature("sso"))
            self.assertEqual(t.limit("seats"), 5)
        self.assertIsNone(src.get("ghost"))
        custom = redis_source(FakeRedis({"app:tenant:id-acme": json.dumps(cached)}), prefix="app:")
        self.assertEqual(custom.get("id-acme").slug, "acme")


class StubAPI(BaseHTTPRequestHandler):
    used = 0
    domain_calls = 0

    def log_message(self, *args):
        pass

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer key":
            return self._send(401, {"error": {"code": "unauthorized", "message": "no"}})
        u = urlparse(self.path)
        if u.path in ("/v1/tenants/acme", "/v1/tenants/id-acme"):
            return self._send(200, {"id": "id-acme", "slug": "acme", "name": "Acme", "status": "active",
                                    "plan": "pro", "features": {"beta": True}, "version": 1})
        if u.path == "/v1/tenants/id-acme/entitlements":
            return self._send(200, {"tenant_id": "id-acme", "plan": "pro", "features": {"sso": True}, "limits": {"api_calls": 2}})
        if u.path == "/v1/domains/resolve":
            StubAPI.domain_calls += 1
            if parse_qs(u.query).get("host") == ["shop.acme.com"]:
                return self._send(200, {"tenant_id": "id-acme", "slug": "acme", "hostname": "shop.acme.com"})
        self._send(404, {"error": {"code": "not_found", "message": "nope"}})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path != "/v1/tenants/id-acme/usage/api_calls":
            return self._send(404, {"error": {"code": "not_found", "message": "nope"}})
        if StubAPI.used >= 2:
            return self._send(429, {"error": {"code": "quota_exceeded", "message": "api_calls limit 2 reached"}})
        StubAPI.used += body["delta"]
        self._send(200, {"metric": "api_calls", "value": StubAPI.used, "limit": 2})


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), StubAPI)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_api_source(self):
        t = api_source(self.base, "key").get("acme")
        self.assertEqual((t.id, dict(t.features), dict(t.limits)), ("id-acme", {"sso": True}, {"api_calls": 2}))
        self.assertIsNone(api_source(self.base, "key").get("ghost"))

    def test_custom_domain_cached(self):
        client = ApiClient(self.base, "key")
        resolver = Resolver(from_subdomain("app.example.com"), from_custom_domain(CachingDomains(client, ttl=60)))
        source = CachingSource(client, ttl=60)
        before = StubAPI.domain_calls
        for _ in range(3):
            self.assertEqual(resolve_tenant(req("shop.acme.com"), resolver, source).tenant.id, "id-acme")
            with self.assertRaises(TenantError) as cm:
                resolve_tenant(req("unknown.org"), resolver, source)
            self.assertEqual(cm.exception.status, 404)
        self.assertEqual(StubAPI.domain_calls - before, 2)

    def test_usage_quota(self):
        rec = UsageRecorder(ApiClient(self.base, "key"))
        self.assertEqual(rec.record("id-acme", "api_calls")["value"], 1)
        self.assertEqual(rec.record("id-acme", "api_calls")["value"], 2)
        with self.assertRaises(QuotaExceeded) as cm:
            rec.record("id-acme", "api_calls")
        self.assertEqual((cm.exception.status, cm.exception.code), (429, "quota_exceeded"))


@require_feature("sso")
def sso_app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [("hello " + environ["tenarium.tenant"].slug + " " + current_tenant().slug).encode()]


def call_wsgi(app, environ):
    seen = {}

    def start_response(status, headers):
        seen["status"] = int(status.split()[0])

    body = b"".join(app(environ, start_response))
    return seen["status"], body.decode()


class WSGITests(unittest.TestCase):
    def test_wsgi_and_require_feature(self):
        app = TenantMiddleware(sso_app, Resolver(from_header("X-Tenant")), MemorySource(ACME, GLOBEX, FROZEN))
        self.assertEqual(call_wsgi(app, {"HTTP_X_TENANT": "acme"}), (200, "hello acme acme"))
        status, body = call_wsgi(app, {"HTTP_X_TENANT": "globex"})
        self.assertEqual((status, json.loads(body)["error"]["code"]), (403, "feature_disabled"))
        self.assertEqual(call_wsgi(app, {"HTTP_X_TENANT": "frozen"})[0], 403)
        self.assertEqual(call_wsgi(app, {"HTTP_X_TENANT": "ghost"})[0], 404)
        self.assertEqual(call_wsgi(app, {})[0], 404)
        self.assertIsNone(current_tenant())


class ASGITests(unittest.TestCase):
    def test_asgi_and_require_feature(self):
        @require_feature("sso")
        async def app(scope, receive, send):
            body = ("hello %s %s" % (scope["state"]["tenant"].slug, current_tenant().slug)).encode()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": body})

        mw = TenantASGIMiddleware(app, Resolver(from_subdomain("app.example.com")), MemorySource(ACME, GLOBEX, FROZEN))

        async def call(host):
            sent = []

            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(m):
                sent.append(m)

            await mw({"type": "http", "path": "/", "headers": [(b"host", host.encode())]}, receive, send)
            return sent[0]["status"], sent[1]["body"].decode()

        async def run():
            self.assertEqual(await call("acme.app.example.com"), (200, "hello acme acme"))
            status, body = await call("globex.app.example.com")
            self.assertEqual((status, json.loads(body)["error"]["code"]), (403, "feature_disabled"))
            self.assertEqual((await call("frozen.app.example.com"))[0], 403)
            self.assertEqual((await call("ghost.app.example.com"))[0], 404)

            passthrough = []

            async def inner(scope, receive, send):
                passthrough.append(scope["type"])

            await TenantASGIMiddleware(inner, Resolver(), MemorySource())({"type": "lifespan"}, None, None)
            self.assertEqual(passthrough, ["lifespan"])

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
