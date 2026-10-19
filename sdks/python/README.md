# tenarium-plugin

Write [Tenarium](https://github.com/AimTune/tenarium) plugins in Python 3.9+, using only the
standard library.

```python
from tenarium_plugin import Plugin, reject, serve

plugin = Plugin(id="naming", name="Naming policy", version="1.0.0")

@plugin.init
def init(r):
    blocked = r.config.get("blocked", [])

    @r.hook("tenant.before_create")
    def check(req):
        if any(w in req["tenant"]["slug"] for w in blocked):
            reject("slug contains a blocked word")

    @r.subscribe("crm-sync", ["tenant.created", "tenant.deleted"])
    def sync(event):
        ...  # delivered at least once; raise to retry

if __name__ == "__main__":
    serve(plugin)
```

```yaml
plugins:
  - plugin: external
    name: naming
    config:
      command: ["python3", "naming.py"]
      config: {blocked: [admin, root]}
```

Also available: `r.provisioner(name, provision, deprovision)`, `@r.route("GET /path")`,
`@r.authorizer(name)` and `@r.authenticator(name)` (raise `NoCredentials` to pass), and
`r.user_directory(obj)` and `r.mailer(obj_or_fn)` to provide Tenarium's user directory and
mailer (raise `NotFound`, `Unsupported`, `Forbidden` or `InvalidCredentials` so Tenarium can tell
the cases apart). See [examples/guard.py](examples/guard.py),
[examples/directory.py](examples/directory.py), the tests
(`python -m unittest discover -s tests`) and the
[protocol documentation](../../docs/plugins/external.md).
