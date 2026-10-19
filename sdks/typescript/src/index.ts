// Tenarium external plugin SDK for TypeScript / JavaScript (Node.js 22+).
// Zero dependencies: implements the HTTP/JSON plugin protocol (v1) with
// node:http. See docs/plugins/external.md for the protocol.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

export const PROTOCOL_VERSION = 1;

// ---- domain types (mirror pkg/sdk) -----------------------------------------

export type TenantStatus = "provisioning" | "active" | "suspended" | "failed" | "deleting" | "deleted";

export interface Tenant {
  id: string;
  slug: string;
  name: string;
  parent_id?: string;
  status: TenantStatus;
  status_reason?: string;
  plan?: string;
  labels?: Record<string, string>;
  settings?: Record<string, unknown>;
  features?: Record<string, boolean>;
  limits?: Record<string, number>;
  version: number;
  created_at: string;
  updated_at: string;
  deleted_at?: string;
}

export interface Member {
  id: string;
  tenant_id: string;
  user_id?: string;
  email: string;
  role: string;
  status: "invited" | "active";
  invited_by?: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface Principal {
  subject: string;
  kind: string;
  authenticator: string;
  tenant_id?: string;
  roles?: string[];
  claims?: Record<string, unknown>;
}

/** CloudEvents 1.0 structured event as delivered to subscriptions. */
export interface CloudEvent<T = unknown> {
  specversion: "1.0";
  id: string;
  source: string;
  type: string;
  subject?: string;
  time: string;
  datacontenttype?: string;
  tenantid?: string;
  actor?: string;
  sequence: string;
  /** W3C trace context of the request that caused the event, if traced. */
  traceparent?: string;
  tracestate?: string;
  data?: T;
}

export type HookPoint =
  | "tenant.before_create"
  | "tenant.before_update"
  | "tenant.before_suspend"
  | "tenant.before_resume"
  | "tenant.before_delete"
  | "member.before_add"
  | "member.before_update"
  | "member.before_remove"
  | "user.before_create"
  | "user.before_update";

export interface User {
  id: string;
  email: string;
  name?: string;
  status: "invited" | "active" | "disabled";
  email_verified: boolean;
  roles?: string[];
  directory: string;
  external_id?: string;
  attributes?: Record<string, string>;
  version: number;
  created_at?: string;
  updated_at?: string;
  last_login_at?: string;
}

/** An email to send (mirrors sdk.Message). */
export interface Message {
  to: string[];
  subject: string;
  text: string;
  html?: string;
  /** Kind of message: "invitation", "password_reset", "email_verification", ... */
  tag?: string;
}

export interface HookRequest {
  point: HookPoint;
  /** Absent for user hooks. */
  tenant?: Tenant;
  previous?: Tenant;
  member?: Member;
  user?: User;
}

export interface Resource {
  type: string;
  id?: string;
  tenant_id?: string;
}

export type Decision = "allow" | "deny" | "abstain";

export interface Manifest {
  id: string;
  name: string;
  version: string;
  description?: string;
  config_schema?: unknown;
}

// ---- plugin definition ------------------------------------------------------

/** Throw from a hook to refuse the operation with a client-visible reason. */
export class RejectError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`rejected: ${reason}`);
    this.reason = reason;
  }
}

export const reject = (reason: string): never => {
  throw new RejectError(reason);
};

/** Throw from an authenticator when the request has no credentials it understands. */
export class NoCredentialsError extends Error {
  constructor() {
    super("no credentials");
  }
}

/**
 * Errors with a protocol code. Tenarium maps the code back to the matching
 * Go error (sdk.ErrNotFound, sdk.ErrUnsupported, ...), so throw these from
 * directories and mailers where the meaning matters.
 */
export class PluginError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

/** The user (or other entity) does not exist. */
export class NotFoundError extends PluginError {
  constructor(message = "not found") {
    super("not_found", 404, message);
  }
}

/** The operation is not supported, e.g. passwords managed elsewhere. */
export class UnsupportedError extends PluginError {
  constructor(message = "not supported") {
    super("unsupported", 501, message);
  }
}

/** The operation is not allowed. */
export class ForbiddenError extends PluginError {
  constructor(message = "forbidden") {
    super("forbidden", 403, message);
  }
}

/** Throw from verifyPassword when the password is wrong. */
export class InvalidCredentialsError extends PluginError {
  constructor(message = "invalid credentials") {
    super("invalid_credentials", 403, message);
  }
}

/**
 * Keeps user identities outside Tenarium (mirrors sdk.UserDirectory). All
 * methods must be idempotent: Tenarium retries after timeouts.
 */
export interface UserDirectory {
  /** Defaults to the plugin instance name. */
  name?: string;
  /** Creates the identity and returns its ID in the directory; for a known email, returns the existing ID. */
  createUser(user: User): Promise<string> | string;
  /** Applies email, name, status and attribute changes. Throw NotFoundError for an unknown user. */
  updateUser(user: User): Promise<void> | void;
  deleteUser(user: User): Promise<void> | void;
  /** Throw UnsupportedError if passwords are managed only in the directory's own UI. */
  setPassword(user: User, password: string): Promise<void> | void;
  /** Optional: enables Tenarium's password login. Throw InvalidCredentialsError for a wrong password. */
  verifyPassword?(user: User, password: string): Promise<void> | void;
  /** Optional: sends the directory's own invitation email instead of Tenarium's. */
  sendInvitation?(user: User): Promise<void> | void;
}

/** Sends email (mirrors sdk.Mailer). */
export interface Mailer {
  /** Defaults to the plugin instance name. */
  name?: string;
  send(message: Message): Promise<void> | void;
}

export interface SubscribeOptions {
  maxAttempts?: number;
  timeoutMs?: number;
  startAtEnd?: boolean;
}

export interface RouteRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: IncomingMessage["headers"];
  body: string;
  principal?: Principal;
}

export interface RouteResponse {
  status?: number;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface Provisioner {
  name: string;
  provision(tenant: Tenant): Promise<void> | void;
  deprovision(tenant: Tenant): Promise<void> | void;
}

export interface AuthenticateRequest {
  method: string;
  path: string;
  headers: Record<string, string[]>;
}

export interface Logger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

/** Passed to init; mirrors sdk.Registrar. */
export interface Registrar<C> {
  config: C;
  instance: string;
  log: Logger;
  subscribe(name: string, types: string[], handler: (e: CloudEvent) => Promise<void> | void, opts?: SubscribeOptions): void;
  hook(point: HookPoint, handler: (req: HookRequest) => Promise<void> | void, priority?: number): void;
  provisioner(p: Provisioner): void;
  /** pattern is "METHOD /path", matched exactly, relative to /v1/plugins/{instance}. */
  route(pattern: string, handler: (req: RouteRequest) => Promise<RouteResponse> | RouteResponse): void;
  authorizer(name: string, fn: (p: Principal, action: string, res: Resource) => Promise<Decision> | Decision): void;
  authenticator(name: string, fn: (req: AuthenticateRequest) => Promise<Principal> | Principal): void;
  /** Offers a user directory (at most one; a later call replaces it). */
  userDirectory(d: UserDirectory): void;
  /** Offers a mailer (at most one; a later call replaces it). */
  mailer(m: Mailer): void;
}

export interface Plugin<C = Record<string, unknown>> {
  manifest: Manifest;
  init(r: Registrar<C>): Promise<void> | void;
  health?(): Promise<void> | void;
  stop?(): Promise<void> | void;
}

export const definePlugin = <C = Record<string, unknown>>(p: Plugin<C>): Plugin<C> => p;

// ---- protocol server --------------------------------------------------------

interface Registry {
  subs: Map<string, { types: string[]; handler: (e: CloudEvent) => Promise<void> | void; opts: SubscribeOptions }>;
  hooks: { point: HookPoint; priority: number; handler: (req: HookRequest) => Promise<void> | void }[];
  provisioners: Map<string, Provisioner>;
  routes: Map<string, (req: RouteRequest) => Promise<RouteResponse> | RouteResponse>;
  authorizers: Map<string, (p: Principal, action: string, res: Resource) => Promise<Decision> | Decision>;
  authenticators: Map<string, (req: AuthenticateRequest) => Promise<Principal> | Principal>;
  directory?: UserDirectory;
  mailer?: Mailer;
}

const consoleLogger = (instance: string): Logger => {
  const line = (level: string, msg: string, fields?: Record<string, unknown>) =>
    console.error(JSON.stringify({ time: new Date().toISOString(), level, msg, instance, ...fields }));
  return {
    info: (m, f) => line("INFO", m, f),
    warn: (m, f) => line("WARN", m, f),
    error: (m, f) => line("ERROR", m, f),
  };
};

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface ServeOptions {
  /** host:port; defaults to TENARIUM_PLUGIN_ADDR or 127.0.0.1:9333. */
  addr?: string;
  /** shared secret; defaults to TENARIUM_PLUGIN_SECRET. */
  secret?: string;
}

/** Starts the plugin server. Resolves once listening. */
export function serve<C>(plugin: Plugin<C>, opts: ServeOptions = {}) {
  const addr = opts.addr ?? process.env.TENARIUM_PLUGIN_ADDR ?? "127.0.0.1:9333";
  const secret = Buffer.from(opts.secret ?? process.env.TENARIUM_PLUGIN_SECRET ?? "");
  // Proves to Tenarium (managed mode) that this is the process it started.
  const proofKey = process.env.TENARIUM_PLUGIN_PROOF_KEY ?? "";
  let reg: Registry | undefined;
  let initialised = false;

  const authorized = (req: IncomingMessage) => {
    if (secret.length === 0) return true;
    const got = Buffer.from((req.headers.authorization ?? "").replace(/^Bearer /, ""));
    return got.length === secret.length && timingSafeEqual(got, secret);
  };

  const current = () => {
    if (!reg) throw new HttpError(409, "plugin not initialised");
    return reg;
  };

  const handle = async (req: IncomingMessage, raw: string): Promise<{ status: number; body?: unknown; headers?: Record<string, string> }> => {
    const url = new URL(req.url ?? "/", "http://plugin");
    const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const json = () => (raw ? JSON.parse(raw) : {});

    if (req.method === "GET" && url.pathname === "/health") {
      if (initialised && plugin.health) await plugin.health();
      return { status: 200, body: { status: "ok", initialised } };
    }
    if (req.method === "POST" && url.pathname === "/init") {
      const body = json();
      if (body.protocol !== PROTOCOL_VERSION) throw new HttpError(400, `unsupported protocol ${body.protocol}`);
      if (initialised && plugin.stop) await plugin.stop();
      const next: Registry = {
        subs: new Map(), hooks: [], provisioners: new Map(), routes: new Map(), authorizers: new Map(), authenticators: new Map(),
      };
      const registrar: Registrar<C> = {
        config: (body.config ?? {}) as C,
        instance: body.instance,
        log: consoleLogger(body.instance),
        subscribe: (name, types, handler, o = {}) => void next.subs.set(name, { types, handler, opts: o }),
        hook: (point, handler, priority = 0) => void next.hooks.push({ point, handler, priority }),
        provisioner: (p) => void next.provisioners.set(p.name, p),
        route: (pattern, handler) => void next.routes.set(pattern, handler),
        authorizer: (name, fn) => void next.authorizers.set(name, fn),
        authenticator: (name, fn) => void next.authenticators.set(name, fn),
        userDirectory: (d) => void (next.directory = d),
        mailer: (m) => void (next.mailer = m),
      };
      try {
        await plugin.init(registrar);
      } catch (e) {
        throw new HttpError(400, (e as Error).message);
      }
      next.hooks.sort((a, b) => a.priority - b.priority);
      reg = next;
      initialised = true;
      const points = [...new Map(next.hooks.map((h) => [h.point, h.priority])).entries()];
      return {
        status: 200,
        body: {
          protocol: PROTOCOL_VERSION,
          proof: proofKey && body.nonce ? createHmac("sha256", proofKey).update(String(body.nonce)).digest("hex") : undefined,
          manifest: plugin.manifest,
          subscriptions: [...next.subs].map(([name, s]) => ({
            name, types: s.types, max_attempts: s.opts.maxAttempts, timeout_ms: s.opts.timeoutMs, start_at_end: s.opts.startAtEnd,
          })),
          hooks: points.map(([point, priority]) => ({ point, priority })),
          provisioners: [...next.provisioners.keys()],
          routes: [...next.routes.keys()],
          authorizers: [...next.authorizers.keys()],
          authenticators: [...next.authenticators.keys()],
          user_directory: next.directory && {
            name: next.directory.name || undefined,
            verify_password: typeof next.directory.verifyPassword === "function" || undefined,
            send_invitation: typeof next.directory.sendInvitation === "function" || undefined,
          },
          mailer: next.mailer && { name: next.mailer.name || undefined },
        },
      };
    }
    if (req.method === "POST" && parts[0] === "events" && parts.length === 2) {
      const sub = current().subs.get(parts[1]);
      if (!sub) throw new HttpError(404, `unknown subscription ${parts[1]}`);
      await sub.handler(json());
      return { status: 204 };
    }
    if (req.method === "POST" && parts[0] === "hooks" && parts.length === 2) {
      const hookReq: HookRequest = { ...json(), point: parts[1] as HookPoint };
      try {
        for (const h of current().hooks) if (h.point === hookReq.point) await h.handler(hookReq);
      } catch (e) {
        if (e instanceof RejectError) return { status: 200, body: { reject: e.reason } };
        throw e;
      }
      return { status: 200, body: { tenant: hookReq.tenant, member: hookReq.member, user: hookReq.user } };
    }
    if (req.method === "POST" && parts[0] === "provisioners" && parts.length === 3) {
      const p = current().provisioners.get(parts[1]);
      if (!p) throw new HttpError(404, `unknown provisioner ${parts[1]}`);
      if (parts[2] === "provision") await p.provision(json());
      else if (parts[2] === "deprovision") await p.deprovision(json());
      else throw new HttpError(404, `unknown operation ${parts[2]}`);
      return { status: 204 };
    }
    if (req.method === "POST" && parts[0] === "authorize" && parts.length === 2) {
      const fn = current().authorizers.get(parts[1]);
      if (!fn) throw new HttpError(404, `unknown authorizer ${parts[1]}`);
      const { principal, action, resource } = json();
      return { status: 200, body: { decision: await fn(principal, action, resource) } };
    }
    if (req.method === "POST" && parts[0] === "authenticate" && parts.length === 2) {
      const fn = current().authenticators.get(parts[1]);
      if (!fn) throw new HttpError(404, `unknown authenticator ${parts[1]}`);
      try {
        return { status: 200, body: { principal: await fn(json()) } };
      } catch (e) {
        if (e instanceof NoCredentialsError) return { status: 200, body: { no_credentials: true } };
        return { status: 200, body: { error: (e as Error).message } };
      }
    }
    if (req.method === "POST" && parts[0] === "directory" && parts.length === 2) {
      const d = current().directory;
      if (!d) throw new HttpError(404, "plugin offers no user directory");
      const { user, password } = json() as { user: User; password?: string };
      switch (parts[1]) {
        case "create_user": {
          const id = await d.createUser(user);
          if (typeof id !== "string" || id === "") throw new HttpError(500, "directory returned an empty external id");
          return { status: 200, body: { external_id: id } };
        }
        case "update_user":
          await d.updateUser(user);
          break;
        case "delete_user":
          await d.deleteUser(user);
          break;
        case "set_password":
          await d.setPassword(user, password ?? "");
          break;
        case "verify_password":
          if (!d.verifyPassword) throw new UnsupportedError("directory does not verify passwords");
          await d.verifyPassword(user, password ?? "");
          break;
        case "send_invitation":
          if (!d.sendInvitation) throw new UnsupportedError("directory does not send invitations");
          await d.sendInvitation(user);
          break;
        default:
          throw new HttpError(404, `unknown directory operation ${parts[1]}`);
      }
      return { status: 204 };
    }
    if (req.method === "POST" && url.pathname === "/mailer/send") {
      const m = current().mailer;
      if (!m) throw new HttpError(404, "plugin offers no mailer");
      await m.send(json());
      return { status: 204 };
    }
    if (parts[0] === "routes") {
      const path = "/" + parts.slice(1).join("/");
      const handler = current().routes.get(`${req.method} ${path}`);
      if (!handler) throw new HttpError(404, `no route ${req.method} ${path}`);
      const header = req.headers["x-tenarium-principal"];
      const principal = typeof header === "string" ? JSON.parse(Buffer.from(header, "base64url").toString()) : undefined;
      const out = await handler({ method: req.method ?? "GET", path, query: url.searchParams, headers: req.headers, body: raw, principal });
      return { status: out.status ?? 200, body: out.body, headers: out.headers };
    }
    throw new HttpError(404, "not found");
  };

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const send = (status: number, body?: unknown, headers: Record<string, string> = {}) => {
      if (body === undefined) {
        res.writeHead(status, headers).end();
        return;
      }
      res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
    };
    if (!authorized(req)) return send(401, { error: "invalid plugin secret" });
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    try {
      const out = await handle(req, Buffer.concat(chunks).toString());
      send(out.status, out.body, out.headers);
    } catch (e) {
      if (e instanceof PluginError) return send(e.status, { error: e.message, code: e.code });
      send(e instanceof HttpError ? e.status : 500, { error: (e as Error).message });
    }
  });

  const [host, port] = splitAddr(addr);
  const shutdown = async () => {
    server.close();
    if (initialised && plugin.stop) await plugin.stop();
    process.exit(0);
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  return new Promise<typeof server>((resolve) => server.listen(port, host, () => resolve(server)));
}

function splitAddr(addr: string): [string, number] {
  const i = addr.lastIndexOf(":");
  return [addr.slice(0, i) || "127.0.0.1", Number(addr.slice(i + 1))];
}
