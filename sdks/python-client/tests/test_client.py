import json
import os
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from tenarium_client import (  # noqa: E402
    Client,
    ResultDict,
    TenariumError,
    TokenSource,
    etag_of,
    is_not_found,
    is_quota_exceeded,
    is_version_conflict,
    response_of,
)
from tenarium_client import _generated  # noqa: E402

ACME = {
    "id": "11111111-1111-1111-1111-111111111111",
    "slug": "acme",
    "name": "Acme",
    "status": "active",
    "version": 3,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}


class Recorded:
    def __init__(self, method, path, query, headers, body):
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body


class Stub:
    """A local HTTP server whose responses come from a replaceable handler."""

    def __init__(self):
        self.requests = []
        self.handler = lambda r: (404, {"error": {"code": "not_found", "message": "no handler"}}, {})
        stub = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8") if n else ""
                u = urlsplit(self.path)
                rec = Recorded(self.command, u.path, parse_qs(u.query), self.headers, body)
                stub.requests.append(rec)
                out = stub.handler(rec)
                if out is None:  # drop the connection
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                status, payload, headers = out
                if isinstance(payload, bytes):
                    data = payload
                    headers = dict(headers)
                    headers.setdefault("Content-Type", "text/plain")
                elif payload is None:
                    data = b""
                else:
                    data = json.dumps(payload).encode("utf-8")
                    headers = dict(headers)
                    headers.setdefault("Content-Type", "application/json")
                try:
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client gave up (timeout test)

            do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stub = Stub()

    @classmethod
    def tearDownClass(cls):
        cls.stub.close()

    def setUp(self):
        self.stub.requests = []

    def client(self, **kw):
        kw.setdefault("api_key", "tnr_secret")
        c = Client(self.stub.url + "/", **kw)
        c.sleeps = []
        c._sleep = c.sleeps.append  # record backoff instead of waiting
        return c

    def test_credentials_query_path_and_metadata(self):
        self.stub.handler = lambda r: (200, {"items": [ACME]}, {"ETag": '"3"', "X-Request-ID": "req-1"})
        c = self.client()
        page = c.list_tenants(status="active", label=["tier=gold", "region=eu"], include_deleted=False, limit=10)
        self.assertEqual(page["items"][0]["slug"], "acme")
        self.assertIsInstance(page, ResultDict)
        self.assertEqual(page, {"items": [ACME]})
        self.assertEqual(etag_of(page), '"3"')
        self.assertEqual(response_of(page).request_id, "req-1")
        self.assertEqual(page.status, 200)

        r = self.stub.requests[0]
        self.assertEqual((r.method, r.path), ("GET", "/v1/tenants"))
        self.assertEqual(r.headers["Authorization"], "Bearer tnr_secret")
        self.assertEqual(r.query["status"], ["active"])
        self.assertEqual(r.query["label"], ["tier=gold", "region=eu"])
        self.assertEqual(r.query["include_deleted"], ["false"])
        self.assertEqual(r.query["limit"], ["10"])
        self.assertNotIn("plan", r.query)
        self.assertTrue(r.headers["User-Agent"].startswith("tenarium-python-client/"))

        try:
            c.get_member("a/b", "m 1")
        except TenariumError:
            pass
        self.assertEqual(self.stub.requests[1].path, "/v1/tenants/a%2Fb/members/m%201")
        with self.assertRaisesRegex(ValueError, "empty path parameter id"):
            c.get_tenant("")

    def test_if_match_and_patch_not_retried(self):
        self.stub.handler = lambda r: (503, {"error": {"code": "unavailable", "message": "busy"}}, {})
        c = self.client(max_retries=3)
        with self.assertRaises(TenariumError) as cm:
            c.update_tenant("acme", {"plan": "pro"}, if_match=3)
        self.assertEqual(cm.exception.status, 503)
        self.assertEqual(len(self.stub.requests), 1)
        r = self.stub.requests[0]
        self.assertEqual(r.headers["If-Match"], '"3"')
        self.assertEqual(r.headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(r.body), {"plan": "pro"})

        self.stub.handler = lambda r: (412, {"error": {"code": "version_conflict", "message": "changed"}}, {})
        with self.assertRaises(TenariumError) as cm:
            c.update_plan("pro", {"name": "Pro"}, if_match='"7"')
        self.assertTrue(is_version_conflict(cm.exception))
        self.assertEqual(self.stub.requests[1].headers["If-Match"], '"7"')

    def test_automatic_idempotency_key(self):
        calls = {"n": 0}

        def flaky(r):
            calls["n"] += 1
            if calls["n"] < 3:
                return 503, {"error": {"code": "unavailable", "message": "x"}}, {}
            return 201, ACME, {}

        self.stub.handler = flaky
        c = self.client(max_retries=3)
        t = c.create_tenant({"slug": "acme", "name": "Acme"})
        self.assertEqual(t["slug"], "acme")
        self.assertEqual(len(self.stub.requests), 3)
        self.assertEqual(len(c.sleeps), 2)
        key = self.stub.requests[0].headers["Idempotency-Key"]
        self.assertTrue(key and len(key) >= 16)
        self.assertTrue(all(r.headers["Idempotency-Key"] == key for r in self.stub.requests))

        # Without retries: no automatic key, no retry.
        self.stub.requests, calls["n"] = [], 0
        with self.assertRaises(TenariumError):
            self.client().create_tenant({"slug": "acme", "name": "Acme"})
        self.assertEqual(len(self.stub.requests), 1)
        self.assertIsNone(self.stub.requests[0].headers.get("Idempotency-Key"))

        # A non-create POST is retried only with an explicit key.
        self.stub.requests, calls["n"] = [], 0
        with self.assertRaises(TenariumError):
            c.suspend_tenant("acme", {"reason": "x"})
        self.assertEqual(len(self.stub.requests), 1)
        self.stub.requests, calls["n"] = [], 0
        c.suspend_tenant("acme", {"reason": "x"}, idempotency_key="fixed")
        self.assertEqual(len(self.stub.requests), 3)
        self.assertTrue(all(r.headers["Idempotency-Key"] == "fixed" for r in self.stub.requests))

    def test_retry_after_and_error_fields(self):
        calls = {"n": 0}

        def limited(r):
            calls["n"] += 1
            if calls["n"] == 1:
                return 429, {"error": {"code": "rate_limited", "message": "slow down"}}, {"Retry-After": "2"}
            return 200, {"metric": "api_calls", "value": 1}, {}

        self.stub.handler = limited
        c = self.client(max_retries=2)
        item = c.record_usage("acme", "api_calls", {"delta": 1})
        self.assertEqual(item["value"], 1)
        self.assertEqual(c.sleeps, [2.0])
        self.assertTrue(self.stub.requests[0].headers.get("Idempotency-Key"))

        self.stub.requests = []
        self.stub.handler = lambda r: (
            429,
            {"error": {"code": "quota_exceeded", "message": "limit reached", "field": "api_calls"}},
            {"X-Request-ID": "r-9"},
        )
        with self.assertRaises(TenariumError) as cm:
            c.record_usage("acme", "api_calls", {"delta": 1})
        e = cm.exception
        self.assertEqual(len(self.stub.requests), 1)
        self.assertTrue(is_quota_exceeded(e))
        self.assertEqual((e.status, e.code, e.message, e.field, e.request_id), (429, "quota_exceeded", "limit reached", "api_calls", "r-9"))
        self.assertEqual(str(e), "tenarium: 429 quota_exceeded: limit reached (field api_calls) [request r-9]")

    def test_network_errors_and_gateway_errors_are_retried(self):
        calls = {"n": 0}

        def flaky(r):
            calls["n"] += 1
            if calls["n"] == 1:
                return None
            if calls["n"] == 2:
                return 504, {}, {}
            return 200, ACME, {}

        self.stub.handler = flaky
        c = self.client(max_retries=2)
        self.assertEqual(c.get_tenant("acme")["id"], ACME["id"])
        self.assertEqual(calls["n"], 3)

    def test_non_json_and_scim_errors(self):
        self.stub.handler = lambda r: (502, b"bad gateway", {})
        with self.assertRaises(TenariumError) as cm:
            self.client().get_tenant("acme")
        self.assertEqual((cm.exception.code, cm.exception.message), ("", "bad gateway"))

        self.stub.handler = lambda r: (404, {"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "404", "detail": "no such user"}, {})
        with self.assertRaises(TenariumError) as cm:
            self.client().scim_get_user("acme", "u1")
        self.assertTrue(is_not_found(cm.exception))
        self.assertEqual(cm.exception.message, "no such user")

    def test_pagination(self):
        def pages(r):
            if r.path == "/v1/tenants":
                after = (r.query.get("after") or [None])[0]
                if after is None:
                    return 200, {"items": [dict(ACME, slug="a"), dict(ACME, slug="b")], "next": "c2"}, {}
                if after == "c2":
                    return 200, {"items": [dict(ACME, slug="c")], "next": "c3"}, {}
                return 200, {"items": []}, {}
            before = (r.query.get("before") or [None])[0]
            if before is None:
                return 200, {"items": [{"seq": 9}, {"seq": 8}], "next": "8"}, {}
            return 200, {"items": [{"seq": 7}]}, {}

        self.stub.handler = pages
        c = self.client()
        self.assertEqual([t["slug"] for t in c.iter_tenants(status="active", limit=2)], ["a", "b", "c"])
        self.assertEqual([r.query.get("after") for r in self.stub.requests], [None, ["c2"], ["c3"]])
        self.assertTrue(all(r.query["status"] == ["active"] and r.query["limit"] == ["2"] for r in self.stub.requests))

        self.stub.requests = []
        events = list(c.iter_tenant_audit("acme", type=["tenant.*"]))
        self.assertEqual([e["seq"] for e in events], [9, 8, 7])
        self.assertEqual([r.query.get("before") for r in self.stub.requests], [None, ["8"]])
        self.assertEqual(self.stub.requests[1].query["type"], ["tenant.*"])

        self.stub.requests = []
        it = c.iter_tenants()
        next(it)
        self.assertEqual(len(self.stub.requests), 1, "pages are fetched lazily")

    def test_public_operations_send_no_credentials(self):
        self.stub.handler = lambda r: (200, {"access_token": "a", "token_type": "Bearer", "expires_in": 900, "refresh_token": "r"}, {})
        pair = self.client().token({"grant_type": "password", "email": "a@b.c", "password": "pw"})
        self.assertEqual(pair["access_token"], "a")
        self.assertIsNone(self.stub.requests[0].headers.get("Authorization"))

    def test_token_source(self):
        state = {"refreshes": 0, "valid": ""}
        lock = threading.Lock()

        def handler(r):
            if r.path == "/v1/auth/token":
                body = json.loads(r.body)
                with lock:
                    self.assertEqual(body, {"grant_type": "refresh_token", "refresh_token": "r%d" % state["refreshes"]})
                    state["refreshes"] += 1
                    n = state["refreshes"]
                time.sleep(0.02)
                state["valid"] = "a%d" % n
                return 200, {"access_token": "a%d" % n, "token_type": "Bearer", "expires_in": 900, "refresh_token": "r%d" % n}, {}
            if r.headers.get("Authorization") != "Bearer " + state["valid"]:
                return 401, {"error": {"code": "unauthorized", "message": "bad token"}}, {}
            return 200, ACME, {}

        self.stub.handler = handler
        now = [1000000.0]
        saved = []
        pub = Client(self.stub.url)
        ts = TokenSource(
            pub,
            {"access_token": "a0", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r0"},
            clock=lambda: now[0],
            on_refresh=saved.append,
        )
        now[0] += 59
        c = pub.with_options(token_source=ts)

        results = []
        threads = [threading.Thread(target=lambda: results.append(c.get_tenant("acme"))) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 3)
        self.assertEqual(state["refreshes"], 1, "concurrent callers share one refresh")
        self.assertEqual(saved[0]["refresh_token"], "r1")
        self.assertEqual(saved[0]["expires_at"], now[0] + 900)

        state["valid"] = "something-else"
        self.stub.requests = []
        c.get_tenant("acme")
        self.assertEqual(state["refreshes"], 2)
        self.assertEqual([r.path for r in self.stub.requests], ["/v1/tenants/acme", "/v1/auth/token", "/v1/tenants/acme"])

        self.stub.handler = lambda r: (
            (200, {"access_token": "x", "token_type": "Bearer", "expires_in": 900, "refresh_token": "y"}, {})
            if r.path == "/v1/auth/token"
            else (401, {"error": {"code": "unauthorized", "message": "no"}}, {})
        )
        with self.assertRaises(TenariumError) as cm:
            c.get_tenant("acme")
        self.assertEqual(cm.exception.status, 401)

    def test_timeout(self):
        def slow(r):
            time.sleep(0.5)
            return 200, ACME, {}

        self.stub.handler = slow
        with self.assertRaises(OSError):
            self.client(timeout=0.1).get_tenant("acme")

    def test_form_text_empty_and_raw(self):
        def handler(r):
            if r.path.endswith("/metadata"):
                return 200, b"<EntityDescriptor/>", {"Content-Type": "application/samlmetadata+xml"}
            if r.path == "/readyz":
                return 200, {"status": "ok"}, {}
            return 204, None, {}

        self.stub.handler = handler
        c = self.client()
        self.assertEqual(c.saml_metadata("t1"), "<EntityDescriptor/>")
        c.saml_acs("t1", {"SAMLResponse": "PHNhbWw+", "RelayState": "s"}, headers={"X-Test": "1"})
        acs = self.stub.requests[1]
        self.assertEqual(acs.headers["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(acs.body, "SAMLResponse=PHNhbWw%2B&RelayState=s")
        self.assertIsNone(acs.headers.get("Authorization"))
        self.assertEqual(acs.headers["X-Test"], "1")
        self.assertIsNone(c.delete_plan("pro"))
        self.assertEqual(c.call("GET", "/readyz"), {"status": "ok"})

    def test_invalid_base_url_and_with_options(self):
        with self.assertRaises(ValueError):
            Client("localhost:8080")
        with self.assertRaises(ValueError):
            Client("ftp://x")
        c = Client(self.stub.url, api_key="k")
        self.assertEqual(c.with_options(token="t").base_url, self.stub.url)

    def test_generated_types(self):
        self.assertEqual(_generated.Tenant.__required_keys__, frozenset(["id", "slug", "name", "status", "version", "created_at", "updated_at"]))
        self.assertIn("plan", _generated.Tenant.__optional_keys__)
        self.assertIn("key", _generated.CreatedAPIKey.__required_keys__)
        self.assertIn("name", _generated.CreatedAPIKey.__optional_keys__)
        for name in _generated.__all__:
            self.assertTrue(hasattr(_generated, name), name)


if __name__ == "__main__":
    unittest.main()
