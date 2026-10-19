// The guard example (see examples/external-go) written in TypeScript.
// Run directly with Node 22.6+ (type stripping):
//
//   plugins:
//     - plugin: external
//       name: guard-ts
//       config:
//         command: ["node", "sdks/typescript/examples/guard.ts"]
//         config: { forbidden_prefix: "test-" }

import { definePlugin, reject, serve, type Tenant } from "../src/index.ts";

interface Config {
  forbidden_prefix?: string;
}

const events: Record<string, number> = {};
const provisioned: string[] = [];

const plugin = definePlugin<Config>({
  manifest: { id: "guard-ts", name: "Guard (TypeScript example)", version: "1.0.0" },

  init(r) {
    const prefix = r.config.forbidden_prefix ?? "test-";

    r.hook("tenant.before_create", (req) => {
      const tenant = req.tenant!; // always set for tenant hooks
      if (tenant.slug.startsWith(prefix)) reject(`slugs starting with "${prefix}" are not allowed`);
      tenant.labels = { ...tenant.labels, guarded: "true" };
    });

    r.subscribe("count", ["tenant.*"], (e) => {
      events[e.type] = (events[e.type] ?? 0) + 1;
    });

    r.provisioner({
      name: "noop",
      provision: (t: Tenant) => {
        if (!provisioned.includes(t.slug)) provisioned.push(t.slug);
      },
      deprovision: () => {},
    });

    r.authorizer("no-delete", (p, action) =>
      action === "tenants:delete" && !(p.roles ?? []).includes("admin") ? "deny" : "allow",
    );

    r.route("GET /stats", (req) => ({ body: { events, provisioned, caller: req.principal?.subject ?? "" } }));
    r.log.info("guard initialised", { prefix });
  },
});

await serve(plugin);
