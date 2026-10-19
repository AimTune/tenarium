import { ForeignTokenError, InvalidTokenError, type Verifier } from "./jwt.ts";
import type { DomainResolver } from "./sources.ts";
import { TenantError, type Claims } from "./types.ts";

/**
 * The parts of a request the resolver reads. Node's IncomingMessage,
 * Express/Connect requests and fetch Requests all fit.
 */
export interface RequestLike {
  url?: string;
  headers: Headers | Record<string, string | string[] | undefined>;
}

/** A tenant reference found in a request. */
export interface Match {
  source: string;
  /** Tenant ID or slug. */
  ref: string;
  claims?: Claims;
}

/** Finds a tenant reference in a request; null when there is none. */
export interface Extractor {
  readonly name: string;
  /** Marks extractors whose matches come from access tokens. */
  readonly token?: boolean;
  extract(req: RequestLike): Match | null | Promise<Match | null>;
}

export function header(req: RequestLike, name: string): string | undefined {
  const h = req.headers;
  if (typeof (h as Headers).get === "function") return (h as Headers).get(name) ?? undefined;
  const v = (h as Record<string, string | string[] | undefined>)[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

function parsedUrl(req: RequestLike): URL {
  return new URL(req.url ?? "/", "http://localhost");
}

/** The request host, lowercased, without port or trailing dot. */
export function hostOf(req: RequestLike): string {
  let host = header(req, "host");
  if (!host && req.url && /^https?:\/\//i.test(req.url)) host = new URL(req.url).host;
  if (!host) return "";
  host = host.toLowerCase();
  if (host.startsWith("[")) host = host.slice(0, host.indexOf("]") + 1);
  else host = host.replace(/:\d+$/, "");
  return host.replace(/\.$/, "");
}

/** "acme.<baseDomain>" resolves to slug "acme" (single label only). */
export function fromSubdomain(baseDomain: string): Extractor {
  const suffix = "." + baseDomain.toLowerCase().replace(/^\.+|\.+$/g, "");
  return {
    name: "subdomain",
    extract(req) {
      const host = hostOf(req);
      if (!host.endsWith(suffix)) return null;
      const label = host.slice(0, -suffix.length);
      return label && !label.includes(".") ? { source: "subdomain", ref: label } : null;
    },
  };
}

/** Tenant ID or slug from a header such as "X-Tenant-ID". */
export function fromHeader(name: string): Extractor {
  return {
    name: "header",
    extract(req) {
      const v = header(req, name)?.trim();
      return v ? { source: "header", ref: v } : null;
    },
  };
}

/** Paths like "/t/{slug}/..." (prefix must start and end with "/"). */
export function fromPathPrefix(prefix = "/t/"): Extractor {
  return {
    name: "path",
    extract(req) {
      const path = parsedUrl(req).pathname;
      if (!path.startsWith(prefix)) return null;
      const ref = decodeURIComponent(path.slice(prefix.length).split("/")[0]);
      return ref ? { source: "path", ref } : null;
    },
  };
}

/**
 * The tid claim of a Tenarium access token ("Authorization: Bearer ...").
 * Non-JWT bearers and tokens of other issuers are ignored; invalid Tenarium
 * tokens are rejected with 401. Platform tokens (no tid) do not match.
 */
export function fromToken(verifier: Verifier): Extractor {
  return {
    name: "token",
    token: true,
    async extract(req) {
      const m = /^bearer\s+(\S+)\s*$/i.exec(header(req, "authorization") ?? "");
      if (!m) return null;
      try {
        const claims = await verifier.verify(m[1]);
        return claims.tid ? { source: "token", ref: claims.tid, claims } : null;
      } catch (err) {
        if (err instanceof ForeignTokenError) return null;
        if (err instanceof InvalidTokenError) throw new TenantError("unauthorized", err.message, { cause: err });
        throw new TenantError("tenant_unavailable", (err as Error).message, { cause: err });
      }
    },
  };
}

/** Custom hostnames through Tenarium's GET /v1/domains/resolve (wrap the client in cachingDomains). */
export function fromCustomDomain(domains: DomainResolver): Extractor {
  return {
    name: "domain",
    async extract(req) {
      const host = hostOf(req);
      if (!host) return null;
      const d = await domains.resolveDomain(host);
      return d?.tenant_id ? { source: "domain", ref: d.tenant_id } : null;
    },
  };
}

export interface Resolution {
  /** The first match. */
  primary: Match;
  /** The access token match, if any. */
  token?: Match;
  /** The first non-token match (host, header or path). */
  addressed?: Match;
}

/**
 * Tries extractors in order; the first match wins. With a token extractor,
 * resolution continues until both the token's tenant and the addressed
 * tenant are known, so a token cannot be used against another tenant.
 */
export class Resolver {
  readonly extractors: readonly Extractor[];

  constructor(...extractors: Extractor[]) {
    this.extractors = extractors;
  }

  /** Resolves null when nothing matched. */
  async resolve(req: RequestLike): Promise<Resolution | null> {
    let tokensLeft = this.extractors.filter((e) => e.token).length;
    let primary: Match | undefined, token: Match | undefined, addressed: Match | undefined;
    for (const e of this.extractors) {
      if (e.token) tokensLeft--;
      if (addressed && (token || (tokensLeft === 0 && !e.token))) break;
      if (e.token ? token : addressed) continue;
      let m: Match | null;
      try {
        m = await e.extract(req);
      } catch (err) {
        if (err instanceof TenantError) throw err;
        throw new TenantError("tenant_unavailable", (err as Error).message, { cause: err });
      }
      if (!m?.ref) continue;
      primary ??= m;
      if (e.token) token = m;
      else addressed = m;
    }
    return primary ? { primary, token, addressed } : null;
  }
}
