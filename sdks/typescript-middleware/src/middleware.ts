import type { IncomingMessage, ServerResponse } from "node:http";
import type { RequestLike, Resolver } from "./resolver.ts";
import type { Source } from "./sources.ts";
import { TenantError, hasFeature, type Claims, type Tenant, type TenantStatus } from "./types.ts";

export interface TenantOptions {
  resolver: Resolver;
  source: Source;
  /** Statuses allowed to use the app (default ["active"]); others get 403, deleted 404. */
  allowedStatuses?: TenantStatus[];
  /** Let requests without any tenant reference through with tenant = null. */
  optional?: boolean;
}

export interface TenantContext {
  tenant: Tenant | null;
  /** Verified token claims when a Tenarium access token was used. */
  claims?: Claims;
}

async function load(source: Source, ref: string): Promise<Tenant | null> {
  try {
    return await source.get(ref);
  } catch (err) {
    throw new TenantError("tenant_unavailable", (err as Error).message, { cause: err });
  }
}

/**
 * Framework-agnostic core: resolves and loads the request's tenant and
 * enforces status and the token mismatch rule. Throws TenantError.
 */
export async function resolveTenant(req: RequestLike, opts: TenantOptions): Promise<TenantContext> {
  const res = await opts.resolver.resolve(req);
  if (!res) {
    if (opts.optional) return { tenant: null };
    throw new TenantError("tenant_required", "no tenant in request");
  }
  const tenant = await load(opts.source, res.primary.ref);
  if (!tenant || tenant.status === "deleted") throw new TenantError("tenant_not_found", "tenant not found");

  if (res.token && res.addressed) {
    const tokenId = res.token.ref;
    let same: boolean;
    if (res.primary === res.addressed) {
      same = tenant.id === tokenId;
    } else {
      const ref = res.addressed.ref;
      same = ref === tokenId || ref === tenant.slug || (await load(opts.source, ref))?.id === tokenId;
    }
    if (!same) throw new TenantError("tenant_mismatch", "token tenant does not match request tenant");
  }

  const allowed = opts.allowedStatuses ?? ["active"];
  if (!allowed.includes(tenant.status)) throw new TenantError("tenant_inactive", `tenant is ${tenant.status}`);
  return { tenant, claims: res.token?.claims };
}

const contexts = new WeakMap<object, TenantContext>();

/** The tenant resolved for req by one of the adapters, or null. */
export function tenantOf(req: object): Tenant | null {
  return contexts.get(req)?.tenant ?? null;
}

/** The verified token claims for req, if a Tenarium token was used. */
export function claimsOf(req: object): Claims | undefined {
  return contexts.get(req)?.claims;
}

/** Writes a TenantError (or 503 for other errors) as Tenarium-style JSON. */
export function writeError(res: ServerResponse, err: unknown): void {
  const e = err instanceof TenantError ? err : new TenantError("tenant_unavailable", String(err), { cause: err });
  res.statusCode = e.status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(e.toJSON()));
}

type Next = (err?: unknown) => void;
type ConnectRequest = IncomingMessage & { tenant?: Tenant | null; tenantClaims?: Claims };

/**
 * Express/Connect middleware. Sets req.tenant and req.tenantClaims (also
 * available via tenantOf/claimsOf) and answers rejections itself; pass
 * onError to forward them instead, e.g. `onError: (err, req, res, next) => next(err)`.
 */
export function tenantMiddleware(
  opts: TenantOptions & { onError?: (err: unknown, req: ConnectRequest, res: ServerResponse, next: Next) => void },
): (req: ConnectRequest, res: ServerResponse, next: Next) => void {
  return (req, res, next) => {
    resolveTenant(req, opts).then(
      (ctx) => {
        contexts.set(req, ctx);
        req.tenant = ctx.tenant;
        req.tenantClaims = ctx.claims;
        next();
      },
      (err) => (opts.onError ? opts.onError(err, req, res, next) : writeError(res, err)),
    );
  };
}

/** Express/Connect middleware answering 403 unless the request's tenant has feature. */
export function requireFeature(feature: string): (req: ConnectRequest, res: ServerResponse, next: Next) => void {
  return (req, res, next) => {
    const tenant = req.tenant ?? tenantOf(req);
    if (!tenant) return writeError(res, new TenantError("tenant_required", "no tenant in request"));
    if (!hasFeature(tenant, feature)) {
      return writeError(res, new TenantError("feature_disabled", `feature ${feature} not enabled for tenant`));
    }
    next();
  };
}

/**
 * Wraps a plain node:http handler: `http.createServer(withTenant(opts, (req, res, ctx) => ...))`.
 */
export function withTenant(
  opts: TenantOptions,
  handler: (req: IncomingMessage, res: ServerResponse, ctx: TenantContext) => void | Promise<void>,
): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    resolveTenant(req, opts)
      .then(async (ctx) => {
        contexts.set(req, ctx);
        await handler(req, res, ctx);
      }, (err) => writeError(res, err))
      .catch((err) => {
        // The handler failed: not a tenant problem.
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end();
        } else res.destroy(err as Error);
      });
  };
}
