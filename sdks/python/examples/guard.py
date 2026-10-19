"""The guard example (see examples/external-go) written in Python.

    plugins:
      - plugin: external
        name: guard-py
        config:
          command: ["python3", "sdks/python/examples/guard.py"]
          config: {forbidden_prefix: "test-"}
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tenarium_plugin import Plugin, reject, serve  # noqa: E402

plugin = Plugin(id="guard-py", name="Guard (Python example)", version="1.0.0")
events = {}
provisioned = []


@plugin.init
def init(r):
    prefix = r.config.get("forbidden_prefix", "test-")

    @r.hook("tenant.before_create")
    def guard(req):
        if req["tenant"]["slug"].startswith(prefix):
            reject(f'slugs starting with "{prefix}" are not allowed')
        req["tenant"].setdefault("labels", {})
        req["tenant"]["labels"] = {**(req["tenant"]["labels"] or {}), "guarded": "true"}

    @r.subscribe("count", ["tenant.*"])
    def count(event):
        events[event["type"]] = events.get(event["type"], 0) + 1

    def provision(tenant):
        if tenant["slug"] not in provisioned:
            provisioned.append(tenant["slug"])

    r.provisioner("noop", provision, lambda tenant: None)

    @r.authorizer("no-delete")
    def no_delete(principal, action, resource):
        if action == "tenants:delete" and "admin" not in (principal.get("roles") or []):
            return "deny"
        return "allow"

    @r.route("GET /stats")
    def stats(req):
        caller = (req["principal"] or {}).get("subject", "")
        return {"body": {"events": events, "provisioned": provisioned, "caller": caller}}


if __name__ == "__main__":
    serve(plugin)
