import { createPublicKey, verify, type KeyObject, type JsonWebKey } from "node:crypto";
import type { Claims } from "./types.ts";

/** Thrown for non-JWT bearers and tokens of other issuers; fromToken ignores them. */
export class ForeignTokenError extends Error {
  constructor() {
    super("not a tenarium token");
    this.name = "ForeignTokenError";
  }
}

/** Thrown when a Tenarium token fails verification. */
export class InvalidTokenError extends Error {
  constructor(message: string) {
    super(`invalid access token: ${message}`);
    this.name = "InvalidTokenError";
  }
}

export interface VerifierOptions {
  /** Tenarium's key set, "<base>/.well-known/jwks.json". */
  jwksUrl: string;
  /** Expected iss (Tenarium's users.public_url or auth.tokens.issuer). */
  issuer: string;
  /** Expected aud (default "tenarium"). */
  audience?: string;
  /** How long a fetched key set is used, in ms (default 1h). */
  keysTtlMs?: number;
  /** Minimum interval between refreshes caused by unknown kids, in ms (default 30s). */
  minRefreshIntervalMs?: number;
  /** Clock skew tolerance in seconds (default 30). */
  leewaySec?: number;
  fetch?: typeof fetch;
}

const b64url = (s: string): Buffer => Buffer.from(s, "base64url");

function decodeJSON(part: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(b64url(part).toString("utf8"));
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * Verifies ES256 access tokens issued by Tenarium against its JWKS. Keys are
 * cached and fetched again when a token names an unknown key ID.
 */
export class Verifier {
  readonly issuer: string;
  readonly audience: string;
  #opts: Required<Omit<VerifierOptions, "audience">>;
  #keys = new Map<string, KeyObject>();
  #fetchedAt = 0;
  #inflight: Promise<void> | null = null;

  constructor(opts: VerifierOptions) {
    if (!opts.jwksUrl || !opts.issuer) throw new Error("Verifier needs jwksUrl and issuer");
    this.issuer = opts.issuer;
    this.audience = opts.audience ?? "tenarium";
    this.#opts = {
      jwksUrl: opts.jwksUrl,
      issuer: opts.issuer,
      keysTtlMs: opts.keysTtlMs ?? 3_600_000,
      minRefreshIntervalMs: opts.minRefreshIntervalMs ?? 30_000,
      leewaySec: opts.leewaySec ?? 30,
      fetch: opts.fetch ?? globalThis.fetch,
    };
  }

  /** Builds a Verifier from "<baseUrl>/.well-known/openid-configuration". */
  static async discover(baseUrl: string, opts: Partial<VerifierOptions> = {}): Promise<Verifier> {
    const f = opts.fetch ?? globalThis.fetch;
    const res = await f(baseUrl.replace(/\/+$/, "") + "/.well-known/openid-configuration");
    if (!res.ok) throw new Error(`discovery: HTTP ${res.status}`);
    const doc = (await res.json()) as { issuer: string; jwks_uri: string };
    return new Verifier({ ...opts, issuer: doc.issuer, jwksUrl: doc.jwks_uri });
  }

  /**
   * Verifies signature, iss, aud, exp and nbf. Throws ForeignTokenError for
   * non-JWTs and other issuers, InvalidTokenError for bad Tenarium tokens.
   */
  async verify(token: string): Promise<Claims> {
    const parts = token.split(".");
    if (parts.length !== 3) throw new ForeignTokenError();
    const header = decodeJSON(parts[0]);
    const claims = decodeJSON(parts[1]) as Claims | null;
    if (!header || !claims || claims.iss !== this.issuer) throw new ForeignTokenError();
    if (header.alg !== "ES256") throw new InvalidTokenError(`unexpected alg ${String(header.alg)}`);
    const kid = typeof header.kid === "string" ? header.kid : "";
    const key = await this.#key(kid);
    const ok = verify(
      "sha256",
      Buffer.from(`${parts[0]}.${parts[1]}`),
      { key, dsaEncoding: "ieee-p1363" },
      b64url(parts[2]),
    );
    if (!ok) throw new InvalidTokenError("bad signature");
    checkClaims(claims, { issuer: this.issuer, audience: this.audience, leewaySec: this.#opts.leewaySec });
    return claims;
  }

  async #key(kid: string): Promise<KeyObject> {
    const now = Date.now();
    const fresh = this.#fetchedAt > 0 && now - this.#fetchedAt < this.#opts.keysTtlMs;
    let key = this.#keys.get(kid);
    if (key && fresh) return key;
    if (!fresh || now - this.#fetchedAt >= this.#opts.minRefreshIntervalMs) {
      try {
        await this.#refresh();
      } catch (err) {
        if (key) return key; // keep serving a stale key
        throw new Error(`fetch jwks: ${(err as Error).message}`, { cause: err });
      }
      key = this.#keys.get(kid);
    }
    if (!key) throw new InvalidTokenError(`unknown signing key "${kid}"`);
    return key;
  }

  #refresh(): Promise<void> {
    this.#inflight ??= (async () => {
      try {
        const res = await this.#opts.fetch(this.#opts.jwksUrl);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const set = (await res.json()) as { keys?: (JsonWebKey & { kid?: string; use?: string })[] };
        const keys = new Map<string, KeyObject>();
        for (const jwk of set.keys ?? []) {
          if (jwk.kty !== "EC" || jwk.d || (jwk.use && jwk.use !== "sig")) continue;
          keys.set(jwk.kid ?? "", createPublicKey({ key: jwk, format: "jwk" }));
        }
        this.#keys = keys;
        this.#fetchedAt = Date.now();
      } finally {
        this.#inflight = null;
      }
    })();
    return this.#inflight;
  }
}

/** Checks iss, aud, exp and nbf of already decoded claims. */
export function checkClaims(
  claims: Claims,
  expect: { issuer: string; audience?: string; leewaySec?: number; now?: number },
): void {
  const now = expect.now ?? Math.floor(Date.now() / 1000);
  const leeway = expect.leewaySec ?? 30;
  if (claims.iss !== expect.issuer) throw new InvalidTokenError("issuer mismatch");
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expect.audience ?? "tenarium")) throw new InvalidTokenError("audience mismatch");
  if (typeof claims.exp !== "number") throw new InvalidTokenError("no expiry");
  if (now - leeway >= claims.exp) throw new InvalidTokenError("token expired");
  if (typeof claims.nbf === "number" && now + leeway < claims.nbf) throw new InvalidTokenError("token not yet valid");
}
