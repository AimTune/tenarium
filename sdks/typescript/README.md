# @tenarium/plugin-sdk

Write [Tenarium](https://github.com/AimTune/tenarium) plugins in TypeScript or JavaScript. It
has no dependencies and runs directly on Node.js 22.6+, which executes TypeScript natively.

```ts
import { definePlugin, reject, serve } from "@tenarium/plugin-sdk";

const plugin = definePlugin<{ blocked?: string[] }>({
  manifest: { id: "naming", name: "Naming policy", version: "1.0.0" },
  init(r) {
    r.hook("tenant.before_create", (req) => {
      if (r.config.blocked?.some((w) => req.tenant.slug.includes(w))) reject("slug contains a blocked word");
    });
    r.subscribe("crm-sync", ["tenant.created", "tenant.deleted"], async (event) => {
      await fetch("https://crm.internal/tenants", { method: "POST", body: JSON.stringify(event.data) });
    });
  },
});

await serve(plugin);
```

Register it in Tenarium:

```yaml
plugins:
  - plugin: external
    name: naming
    config:
      command: ["node", "naming.ts"]
      config: {blocked: [admin, root]}
```

API: `r.subscribe`, `r.hook`, `r.provisioner`, `r.route`, `r.authorizer`, `r.authenticator`,
`r.userDirectory`, `r.mailer`, `r.config`, `r.log`. Throw `reject(reason)` from hooks and
`new NoCredentialsError()` from authenticators. Directories and mailers throw `NotFoundError`,
`UnsupportedError`, `ForbiddenError` or `InvalidCredentialsError` so Tenarium can tell the cases
apart. See [examples/guard.ts](examples/guard.ts), [examples/directory.ts](examples/directory.ts)
(a user directory and mailer), the tests (`npm test`) and the
[protocol documentation](../../docs/plugins/external.md).
