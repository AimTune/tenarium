"""Tenarium external plugin SDK for Python 3.9+ (standard library only).

Implements the HTTP/JSON plugin protocol (v1); see docs/plugins/external.md.

    from tenarium_plugin import Plugin, reject, serve

    plugin = Plugin(id="audit", name="Audit", version="1.0.0")

    @plugin.init
    def init(r):
        @r.subscribe("log", ["tenant.*"])
        def log(event):
            print(event["type"])

    serve(plugin)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlsplit

PROTOCOL_VERSION = 1

__all__ = [
    "Plugin", "Registrar", "RejectError", "NoCredentials", "reject", "serve", "make_server", "PROTOCOL_VERSION",
    "PluginError", "NotFound", "Unsupported", "Forbidden", "InvalidCredentials",
]


class RejectError(Exception):
    """Raise from a hook to refuse an operation with a client-visible reason."""

    def __init__(self, reason: str):
        super().__init__(f"rejected: {reason}")
        self.reason = reason


def reject(reason: str) -> None:
    raise RejectError(reason)


class NoCredentials(Exception):
    """Raise from an authenticator when the request has no credentials it understands."""


class PluginError(Exception):
    """An error with a protocol code. Tenarium maps the code back to the
    matching Go error (sdk.ErrNotFound, sdk.ErrUnsupported, ...); raise the
    subclasses below from directories and mailers where the meaning matters."""

    code = ""
    status = 500

    def __init__(self, message: str = ""):
        super().__init__(message or self.code.replace("_", " "))


class NotFound(PluginError):
    """The user (or other entity) does not exist."""

    code, status = "not_found", 404


class Unsupported(PluginError):
    """The operation is not supported, e.g. passwords managed elsewhere."""

    code, status = "unsupported", 501


class Forbidden(PluginError):
    """The operation is not allowed."""

    code, status = "forbidden", 403


class InvalidCredentials(PluginError):
    """Raise from verify_password when the password is wrong."""

    code, status = "invalid_credentials", 403


_DIRECTORY_OPS = ("create_user", "update_user", "delete_user", "set_password", "verify_password", "send_invitation")


class _HTTPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Registrar:
    """Passed to the plugin's init function; mirrors sdk.Registrar."""

    def __init__(self, instance: str, config: Dict[str, Any]):
        self.instance = instance
        self.config = config or {}
        self.log = logging.getLogger(f"tenarium.plugin.{instance}")
        self.subs: Dict[str, Dict[str, Any]] = {}
        self.hooks: List[Dict[str, Any]] = []
        self.provisioners: Dict[str, Dict[str, Callable]] = {}
        self.routes: Dict[str, Callable] = {}
        self.authorizers: Dict[str, Callable] = {}
        self.authenticators: Dict[str, Callable] = {}
        self.directory: Any = None
        self.directory_name: Optional[str] = None
        self.mailer_send: Optional[Callable[[Dict[str, Any]], None]] = None
        self.mailer_name: Optional[str] = None

    def subscribe(self, name: str, types: List[str], max_attempts: int = 0, timeout_ms: int = 0, start_at_end: bool = False):
        def deco(fn):
            self.subs[name] = {"fn": fn, "types": types, "max_attempts": max_attempts,
                               "timeout_ms": timeout_ms, "start_at_end": start_at_end}
            return fn
        return deco

    def hook(self, point: str, priority: int = 0):
        def deco(fn):
            self.hooks.append({"point": point, "priority": priority, "fn": fn})
            return fn
        return deco

    def provisioner(self, name: str, provision: Callable, deprovision: Callable) -> None:
        self.provisioners[name] = {"provision": provision, "deprovision": deprovision}

    def route(self, pattern: str):
        """pattern is "METHOD /path" relative to /v1/plugins/{instance}."""
        def deco(fn):
            self.routes[pattern] = fn
            return fn
        return deco

    def authorizer(self, name: str):
        def deco(fn):
            self.authorizers[name] = fn
            return fn
        return deco

    def authenticator(self, name: str):
        def deco(fn):
            self.authenticators[name] = fn
            return fn
        return deco

    def user_directory(self, directory: Any, name: Optional[str] = None) -> None:
        """Offers a user directory (at most one; a later call replaces it).

        directory is any object with these methods, each receiving the user
        as a dict (mirrors sdk.UserDirectory; all must be idempotent):

        - create_user(user) -> str: the user's ID in the directory (the
          existing one for a known email)
        - update_user(user), delete_user(user)
        - set_password(user, password): raise Unsupported if passwords are
          managed elsewhere
        - verify_password(user, password), optional: enables password login;
          raise InvalidCredentials for a wrong password
        - send_invitation(user), optional: sends the directory's own
          invitation instead of Tenarium's

        Raise NotFound for unknown users. The name defaults to
        directory.name, then to the instance name.
        """
        for op in ("create_user", "update_user", "delete_user", "set_password"):
            if not callable(getattr(directory, op, None)):
                raise TypeError(f"user directory lacks {op}()")
        self.directory = directory
        self.directory_name = name or getattr(directory, "name", None)

    def mailer(self, mailer: Any, name: Optional[str] = None) -> None:
        """Offers a mailer (at most one; a later call replaces it): an object
        with send(message) or a function taking the message dict
        ({"to", "subject", "text", "html", "tag"})."""
        send = getattr(mailer, "send", None)
        if not callable(send):
            if not callable(mailer):
                raise TypeError("mailer must have send(message) or be callable")
            send = mailer
        self.mailer_send = send
        self.mailer_name = name or getattr(mailer, "name", None)

    def _init_response(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        points: Dict[str, int] = {}
        for h in self.hooks:
            points.setdefault(h["point"], h["priority"])
        resp: Dict[str, Any] = {
            "protocol": PROTOCOL_VERSION,
            "manifest": manifest,
            "subscriptions": [
                {"name": n, "types": s["types"], "max_attempts": s["max_attempts"],
                 "timeout_ms": s["timeout_ms"], "start_at_end": s["start_at_end"]}
                for n, s in self.subs.items()
            ],
            "hooks": [{"point": p, "priority": pr} for p, pr in points.items()],
            "provisioners": list(self.provisioners),
            "routes": list(self.routes),
            "authorizers": list(self.authorizers),
            "authenticators": list(self.authenticators),
        }
        if self.directory is not None:
            spec: Dict[str, Any] = {}
            if self.directory_name:
                spec["name"] = self.directory_name
            if callable(getattr(self.directory, "verify_password", None)):
                spec["verify_password"] = True
            if callable(getattr(self.directory, "send_invitation", None)):
                spec["send_invitation"] = True
            resp["user_directory"] = spec
        if self.mailer_send is not None:
            resp["mailer"] = {"name": self.mailer_name} if self.mailer_name else {}
        return resp


class Plugin:
    def __init__(self, id: str, name: str, version: str, description: str = "", config_schema: Optional[dict] = None):
        self.manifest = {"id": id, "name": name, "version": version, "description": description}
        if config_schema is not None:
            self.manifest["config_schema"] = config_schema
        self._init: Optional[Callable[[Registrar], None]] = None
        self._health: Optional[Callable[[], None]] = None
        self._stop: Optional[Callable[[], None]] = None

    def init(self, fn: Callable[[Registrar], None]):
        self._init = fn
        return fn

    def health(self, fn: Callable[[], None]):
        self._health = fn
        return fn

    def stop(self, fn: Callable[[], None]):
        self._stop = fn
        return fn


class _State:
    def __init__(self, plugin: Plugin, secret: str):
        self.plugin = plugin
        self.secret = secret.encode()
        # Proves to Tenarium (managed mode) that this is the process it started.
        self.proof_key = os.environ.get("TENARIUM_PLUGIN_PROOF_KEY", "").encode()
        self.reg: Optional[Registrar] = None
        self.lock = threading.Lock()

    def current(self) -> Registrar:
        if self.reg is None:
            raise _HTTPError(409, "plugin not initialised")
        return self.reg

    def handle(self, method: str, raw_path: str, headers, body: bytes):
        url = urlsplit(raw_path)
        parts = [unquote(p) for p in url.path.split("/") if p]
        data = json.loads(body) if body else {}

        if method == "GET" and url.path == "/health":
            if self.reg is not None and self.plugin._health:
                self.plugin._health()
            return 200, {"status": "ok", "initialised": self.reg is not None}, {}
        if method == "POST" and url.path == "/init":
            if data.get("protocol") != PROTOCOL_VERSION:
                raise _HTTPError(400, f"unsupported protocol {data.get('protocol')}")
            with self.lock:
                if self.reg is not None and self.plugin._stop:
                    self.plugin._stop()
                reg = Registrar(data.get("instance", ""), data.get("config") or {})
                try:
                    if self.plugin._init:
                        self.plugin._init(reg)
                except Exception as e:  # noqa: BLE001 - report init errors to Tenarium
                    raise _HTTPError(400, str(e))
                reg.hooks.sort(key=lambda h: h["priority"])
                self.reg = reg
            resp = reg._init_response(self.plugin.manifest)
            if self.proof_key and data.get("nonce"):
                resp["proof"] = hmac.new(self.proof_key, str(data["nonce"]).encode(), hashlib.sha256).hexdigest()
            return 200, resp, {}
        if method == "POST" and len(parts) == 2 and parts[0] == "events":
            sub = self.current().subs.get(parts[1])
            if sub is None:
                raise _HTTPError(404, f"unknown subscription {parts[1]}")
            sub["fn"](data)
            return 204, None, {}
        if method == "POST" and len(parts) == 2 and parts[0] == "hooks":
            data["point"] = parts[1]
            try:
                for h in self.current().hooks:
                    if h["point"] == parts[1]:
                        h["fn"](data)
            except RejectError as e:
                return 200, {"reject": e.reason}, {}
            return 200, {"tenant": data.get("tenant"), "member": data.get("member"), "user": data.get("user")}, {}
        if method == "POST" and len(parts) == 3 and parts[0] == "provisioners":
            p = self.current().provisioners.get(parts[1])
            if p is None or parts[2] not in ("provision", "deprovision"):
                raise _HTTPError(404, f"unknown provisioner operation {parts[1]}/{parts[2]}")
            p[parts[2]](data)
            return 204, None, {}
        if method == "POST" and len(parts) == 2 and parts[0] == "authorize":
            fn = self.current().authorizers.get(parts[1])
            if fn is None:
                raise _HTTPError(404, f"unknown authorizer {parts[1]}")
            return 200, {"decision": fn(data["principal"], data["action"], data.get("resource", {}))}, {}
        if method == "POST" and len(parts) == 2 and parts[0] == "authenticate":
            fn = self.current().authenticators.get(parts[1])
            if fn is None:
                raise _HTTPError(404, f"unknown authenticator {parts[1]}")
            try:
                return 200, {"principal": fn(data)}, {}
            except NoCredentials:
                return 200, {"no_credentials": True}, {}
            except Exception as e:  # noqa: BLE001
                return 200, {"error": str(e)}, {}
        if method == "POST" and len(parts) == 2 and parts[0] == "directory":
            d = self.current().directory
            if d is None:
                raise _HTTPError(404, "plugin offers no user directory")
            op = parts[1]
            if op not in _DIRECTORY_OPS:
                raise _HTTPError(404, f"unknown directory operation {op}")
            fn = getattr(d, op, None)
            if not callable(fn):
                raise Unsupported(f"directory does not support {op}")
            user = data.get("user") or {}
            if op == "create_user":
                ext = fn(user)
                if not isinstance(ext, str) or not ext:
                    raise _HTTPError(500, "directory returned an empty external id")
                return 200, {"external_id": ext}, {}
            if op in ("set_password", "verify_password"):
                fn(user, data.get("password") or "")
            else:
                fn(user)
            return 204, None, {}
        if method == "POST" and url.path == "/mailer/send":
            send = self.current().mailer_send
            if send is None:
                raise _HTTPError(404, "plugin offers no mailer")
            send(data)
            return 204, None, {}
        if parts and parts[0] == "routes":
            path = "/" + "/".join(parts[1:])
            fn = self.current().routes.get(f"{method} {path}")
            if fn is None:
                raise _HTTPError(404, f"no route {method} {path}")
            principal = None
            if headers.get("X-Tenarium-Principal"):
                raw = headers["X-Tenarium-Principal"]
                principal = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
            req = {"method": method, "path": path, "query": parse_qs(url.query), "headers": dict(headers),
                   "body": body.decode(), "principal": principal}
            out = fn(req) or {}
            return out.get("status", 200), out.get("body"), out.get("headers", {})
        raise _HTTPError(404, "not found")


def make_server(plugin: Plugin, addr: str, secret: str) -> ThreadingHTTPServer:
    """Returns an HTTP server for the plugin protocol without starting it.
    serve() runs one; tests can run one on port 0 in a thread."""
    state = _State(plugin, secret)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # silence per-request logs
            pass

        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if state.secret:
                got = self.headers.get("Authorization", "").removeprefix("Bearer ").encode()
                if not hmac.compare_digest(got, state.secret):
                    return self._send(401, {"error": "invalid plugin secret"}, {})
            try:
                status, payload, headers = state.handle(self.command, self.path, self.headers, body)
            except PluginError as e:
                status, payload, headers = e.status, {"error": str(e), "code": e.code}, {}
            except _HTTPError as e:
                status, payload, headers = e.status, {"error": str(e)}, {}
            except Exception as e:  # noqa: BLE001
                status, payload, headers = 500, {"error": str(e)}, {}
            self._send(status, payload, headers)

        def _send(self, status, payload, headers):
            data = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(status)
            if payload is not None:
                self.send_header("Content-Type", "application/json")
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve

    host, _, port = addr.rpartition(":")
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    server.plugin_state = state  # type: ignore[attr-defined]
    return server


def serve(plugin: Plugin, addr: Optional[str] = None, secret: Optional[str] = None) -> None:
    """Serves the plugin until SIGINT/SIGTERM. Defaults come from the
    TENARIUM_PLUGIN_ADDR and TENARIUM_PLUGIN_SECRET environment variables."""
    addr = addr or os.environ.get("TENARIUM_PLUGIN_ADDR", "127.0.0.1:9333")
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    server = make_server(plugin, addr, secret if secret is not None else os.environ.get("TENARIUM_PLUGIN_SECRET", ""))
    state = server.plugin_state  # type: ignore[attr-defined]

    def shutdown(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    logging.getLogger("tenarium.plugin").info("listening on %s", addr)
    try:
        server.serve_forever()
    finally:
        if state.reg is not None and plugin._stop:
            plugin._stop()
