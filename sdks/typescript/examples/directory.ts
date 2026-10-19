// An in-memory user directory and mailer: the same "memdir" conformance
// plugin as plugins/external/directory_test.go. Use it as a template for a
// directory backed by your own identity system.
//
//   plugins:
//     - plugin: external
//       name: memdir
//       config:
//         command: ["node", "sdks/typescript/examples/directory.ts"]
//   users:
//     directory: memdir
//     mailer: memdir

import {
  definePlugin,
  InvalidCredentialsError,
  NotFoundError,
  serve,
  UnsupportedError,
  type Message,
  type User,
} from "../src/index.ts";

interface Record_ {
  email: string;
  name?: string;
  password?: string;
}

const users = new Map<string, Record_>();
const invited: string[] = [];
const sent: { to: string[]; subject: string; tag?: string }[] = [];

const lookup = (u: User): Record_ => {
  const rec = users.get(u.external_id ?? "");
  if (!rec) throw new NotFoundError(`no user ${u.external_id}`);
  return rec;
};

const plugin = definePlugin({
  manifest: { id: "memdir-ts", name: "Memory directory (TypeScript example)", version: "1.0.0" },

  init(r) {
    r.userDirectory({
      name: "memdir",
      createUser(u) {
        const email = u.email.toLowerCase();
        const id = `ext-${email}`;
        if (!users.has(id)) users.set(id, { email, name: u.name });
        return id;
      },
      updateUser(u) {
        const rec = lookup(u);
        rec.email = u.email.toLowerCase();
        rec.name = u.name;
      },
      deleteUser(u) {
        users.delete(u.external_id ?? "");
      },
      setPassword(u, password) {
        const rec = lookup(u);
        if (rec.email.endsWith("@sso.example")) throw new UnsupportedError("passwords are managed by SSO");
        rec.password = password;
      },
      verifyPassword(u, password) {
        const rec = users.get(u.external_id ?? "");
        if (!rec?.password || rec.password !== password) throw new InvalidCredentialsError();
      },
      sendInvitation(u) {
        invited.push(lookup(u).email);
      },
    });

    r.mailer({
      name: "memmail",
      send(m: Message) {
        if (!m.to?.length) throw new Error("no recipients");
        sent.push({ to: m.to, subject: m.subject, tag: m.tag });
      },
    });

    r.route("GET /outbox", () => ({ body: { invited, sent } }));
  },
});

await serve(plugin);
