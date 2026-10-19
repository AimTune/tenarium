# External plugins (any language)

An external plugin is a small HTTP server. Tenarium calls it to deliver events, run hooks and
provisioners, authenticate and authorize requests, proxy HTTP routes, and act as a user
directory or mailer. Everything the plugin
registers behaves exactly like a built-in registration: subscriptions get cursors, retries and
dead letters, and hooks can reject operations.

SDKs:

- **Go**: `pkg/extplugin`. `extplugin.Serve(p)` runs any `sdk.Plugin` out of process.
- **TypeScript / JavaScript**: [`sdks/typescript`](https://github.com/AimTune/tenarium/tree/main/sdks/typescript) (Node 22.6+, no dependencies).
- **Python**: [`sdks/python`](https://github.com/AimTune/tenarium/tree/main/sdks/python) (3.9+, standard library only).

The three SDKs ship the same example plugins (`guard`, and `directory` for a user directory
and mailer), and one conformance test checks all of them.

## Configuring it in Tenarium

**Managed mode.** Tenarium starts the process, assigns it an address and a secret, captures its
output into Tenarium's log, restarts it with backoff if it crashes (calling `init` again with
the same configuration), and stops it on shutdown:

```yaml
- plugin: external
  name: guard
  config:
    command: ["node", "plugins/guard.ts"]     # or ["python3", "guard.py"], ["./my-plugin"]
    dir: /opt/tenarium
    env: {TENARIUM_API_URL: "http://localhost:8080", TENARIUM_API_KEY: "${GUARD_API_KEY}"}
    inherit_env: [HTTPS_PROXY]                # extra variables to pass through (see below)
    config: {forbidden_prefix: "test-"}       # passed to the plugin's init
    startup_timeout: 30s
    request_timeout: 30s
```

**Remote mode.** The plugin runs elsewhere (another container, a serverless function):

```yaml
- plugin: external
  name: billing
  config:
    url: http://billing-plugin:9000
    secret: ${BILLING_PLUGIN_SECRET}
    config: {...}
```

A managed process gets a minimal environment (`PATH`, `HOME`, locale and temp directories, and
what Windows needs to start programs) plus `env` and anything listed in `inherit_env`. It does
**not** see Tenarium's other environment variables, such as database credentials or other
plugins' secrets.

Registrations are fixed when Tenarium starts. If a restarted plugin reports different
registrations, Tenarium logs a warning; restart Tenarium to apply them.

## TypeScript

```ts
import { definePlugin, reject, serve } from "@tenarium/plugin-sdk";

const plugin = definePlugin<{ forbidden_prefix?: string }>({
  manifest: { id: "guard", name: "Guard", version: "1.0.0" },
  init(r) {
    const prefix = r.config.forbidden_prefix ?? "test-";
    r.hook("tenant.before_create", (req) => {
      if (req.tenant.slug.startsWith(prefix)) reject(`slugs starting with "${prefix}" are not allowed`);
      req.tenant.labels = { ...req.tenant.labels, guarded: "true" };   // mutations are kept
    });
    r.subscribe("audit", ["tenant.*"], async (event) => { /* at-least-once */ });
    r.provisioner({ name: "crm", provision: async (t) => {}, deprovision: async (t) => {} });
    r.authorizer("no-delete", (p, action) => (action === "tenants:delete" && !p.roles?.includes("admin") ? "deny" : "allow"));
    r.route("GET /stats", (req) => ({ body: { caller: req.principal?.subject } }));
  },
});

await serve(plugin);
```

## Python

```python
from tenarium_plugin import Plugin, reject, serve

plugin = Plugin(id="guard", name="Guard", version="1.0.0")

@plugin.init
def init(r):
    @r.hook("tenant.before_create")
    def guard(req):
        if req["tenant"]["slug"].startswith("test-"):
            reject("test tenants are not allowed")

    @r.subscribe("audit", ["tenant.*"])
    def audit(event):
        print(event["type"], event.get("tenantid"))

serve(plugin)
```

## User directories and mailers

An external plugin can provide the [user directory](../users.md) and the mailer, like the
built-in Keycloak, LDAP and SMTP plugins. Select its instance as usual:

```yaml
plugins:
  - plugin: external
    name: corp-directory
    config:
      command: ["node", "directory.ts"]
users:
  directory: corp-directory
  mailer: corp-directory
```

All directory operations must be idempotent: Tenarium retries after timeouts, so a second
`create_user` for the same email returns the existing ID and deleting a missing user succeeds.
`verify_password` (password login) and `send_invitation` (the directory sends its own invitation
email) are optional; Tenarium only uses them when the plugin implements them.

Raise or throw the SDK's error types so Tenarium can tell the cases apart: *not found*
(unknown user), *unsupported* (for example `set_password` when passwords are managed by SSO;
for `send_invitation` Tenarium then falls back to its own email), *invalid credentials*
(`verify_password` rejected the password) and *forbidden*. Any other error is a plain failure.

```ts
import { definePlugin, InvalidCredentialsError, NotFoundError, serve } from "@tenarium/plugin-sdk";

const plugin = definePlugin({
  manifest: { id: "corp-directory", name: "Corporate directory", version: "1.0.0" },
  init(r) {
    r.userDirectory({
      createUser: async (user) => (await corp.upsert(user.email, user.name)).id,   // returns the external ID
      updateUser: async (user) => { if (!(await corp.update(user.external_id, user))) throw new NotFoundError(); },
      deleteUser: async (user) => { await corp.remove(user.external_id); },
      setPassword: async (user, password) => { await corp.setPassword(user.external_id, password); },
      verifyPassword: async (user, password) => { if (!(await corp.check(user.email, password))) throw new InvalidCredentialsError(); },
    });
    r.mailer({ send: async (msg) => { await mail.send(msg.to, msg.subject, msg.text, msg.html); } });
  },
});
await serve(plugin);
```

```python
from tenarium_plugin import InvalidCredentials, NotFound, Plugin, Unsupported, serve

class CorpDirectory:
    def create_user(self, user): return corp.upsert(user["email"], user.get("name"))  # external ID
    def update_user(self, user): ...          # raise NotFound() for an unknown external_id
    def delete_user(self, user): ...
    def set_password(self, user, password): raise Unsupported("managed by SSO")
    def verify_password(self, user, password): ...   # optional; raise InvalidCredentials()
    # send_invitation(self, user) is optional too

plugin = Plugin(id="corp-directory", name="Corporate directory", version="1.0.0")

@plugin.init
def init(r):
    r.user_directory(CorpDirectory())
    r.mailer(lambda message: smtp_send(message))     # or an object with send(message)

serve(plugin)
```

In Go, `extplugin.Serve` serves whatever `r.UserDirectory` and `r.Mailer` registered; return
`sdk.ErrNotFound`, `sdk.ErrUnsupported`, `sdk.ErrForbidden` or `extplugin.ErrInvalidCredentials`
(wrapped or not). See [examples/directory.ts](https://github.com/AimTune/tenarium/blob/main/sdks/typescript/examples/directory.ts) and
[examples/directory.py](https://github.com/AimTune/tenarium/blob/main/sdks/python/examples/directory.py).

Passwords travel in the request body to the plugin, so in remote mode use HTTPS or a private
network. While a managed plugin restarts, directory and mailer calls fail (and a password
login fails) until it is back.

## Protocol (version 1)

Every request from Tenarium carries `Authorization: Bearer <secret>`; plugins must reject
other requests. In managed mode the plugin listens on `$TENARIUM_PLUGIN_ADDR` and reads the
secret from `$TENARIUM_PLUGIN_SECRET`. Bodies are JSON.

**Proving identity (managed mode).** Tenarium also passes `$TENARIUM_PLUGIN_PROOF_KEY`, which is
never sent over the network. `/init` carries a random `nonce`, and the plugin must answer with
`"proof": hex(HMAC-SHA256(proof_key, nonce))`. Without a valid proof Tenarium makes no calls to
the plugin, so another local process that grabs the port while the plugin restarts cannot
impersonate it. Secret and proof key are regenerated on every restart. The SDKs handle all of
this.

A non-2xx response with `{"error": "...", "code": "..."}` is an error. `code` is optional; Tenarium
maps it to the matching Go error and otherwise treats the error as a plain failure. It never
interprets the HTTP status alone (a 404 without a code is an unknown endpoint, not a missing
user), but the SDKs use the status shown:

| `code` | Go error | Status |
|---|---|---|
| `not_found` | `sdk.ErrNotFound` | 404 |
| `unsupported` | `sdk.ErrUnsupported` | 501 |
| `forbidden` | `sdk.ErrForbidden` | 403 |
| `invalid_credentials` | `extplugin.ErrInvalidCredentials` | 403 |

| Request | Body | Response |
|---|---|---|
| `GET /health` | | 2xx when healthy |
| `POST /init` | `{"protocol": 1, "instance": "guard", "config": {...}}` | `InitResponse` (below) |
| `POST /events/{subscription}` | CloudEvent | 2xx; anything else is retried |
| `POST /hooks/{point}` | `{"point", "tenant", "previous", "member"}` | `{"reject": "reason"}` or `{"tenant": ..., "member": ...}` |
| `POST /provisioners/{name}/provision` | Tenant | 2xx |
| `POST /provisioners/{name}/deprovision` | Tenant | 2xx |
| `POST /authorize/{name}` | `{"principal", "action", "resource"}` | `{"decision": "allow" \| "deny" \| "abstain"}` |
| `POST /authenticate/{name}` | `{"method", "path", "headers"}` | `{"principal": ...}`, `{"no_credentials": true}` or `{"error": "..."}` |
| `POST /directory/create_user` | `{"user": User}` | `{"external_id": "..."}` (non-empty) |
| `POST /directory/update_user` | `{"user": User}` | 2xx |
| `POST /directory/delete_user` | `{"user": User}` | 2xx |
| `POST /directory/set_password` | `{"user": User, "password": "..."}` | 2xx |
| `POST /directory/verify_password` | `{"user": User, "password": "..."}` | 2xx if the password is right (only if declared) |
| `POST /directory/send_invitation` | `{"user": User}` | 2xx (only if declared) |
| `POST /mailer/send` | `{"to": [...], "subject", "text", "html", "tag"}` | 2xx |
| `ANY /routes/...` | proxied request | your response |

`InitResponse`:

```json
{
  "protocol": 1,
  "manifest": {"id": "guard", "name": "Guard", "version": "1.0.0"},
  "subscriptions": [{"name": "audit", "types": ["tenant.*"], "max_attempts": 10, "timeout_ms": 30000, "start_at_end": false}],
  "hooks": [{"point": "tenant.before_create", "priority": 0}],
  "provisioners": ["crm"],
  "routes": ["GET /stats"],
  "authenticators": [],
  "authorizers": ["no-delete"],
  "user_directory": {"name": "corp", "verify_password": true, "send_invitation": false},
  "mailer": {"name": "corp-mail"}
}
```

`user_directory` and `mailer` are present only if the plugin offers them; their `name` defaults to
the instance name. `User` is the user as in the REST API, with `external_id` set to the ID
returned by `create_user` (Tenarium's own ID is `id`). Tenarium validates what it gets back:
names and external IDs must be non-empty UTF-8 without control characters or surrounding
spaces (at most 128 and 512 bytes), and response bodies are limited to 8 MiB.

Events carry the W3C trace context of the request that caused them, when tracing is on, in the
optional CloudEvents attributes `traceparent` and `tracestate`.

Routes are proxied from `/v1/plugins/{instance}/...` to `/routes/...` after Tenarium has
authenticated the caller. The client's `Authorization` header is replaced with the plugin
secret, and the caller is passed as base64url-encoded JSON in `X-Tenarium-Principal`.

A plugin that needs to read Tenarium data calls the REST API. The Go SDK provides `sdk.Host`
over REST when `TENARIUM_API_URL` (and `TENARIUM_API_KEY`) are set.
