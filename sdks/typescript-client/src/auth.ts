import type { TokenPair, TokenRequest } from "./generated/types.ts";
import type { RequestOptions } from "./request.ts";

/** Supplies the bearer token for each request. */
export interface TokenProvider {
  token(): string | Promise<string>;
  /**
   * Replaces a token the server rejected with 401. The client calls it at
   * most once per request and retries the request with the new token.
   */
  reauth?(rejected: string): Promise<string>;
}

/** A fixed bearer token or API key. */
export class StaticToken implements TokenProvider {
  readonly #value: string;
  constructor(value: string) {
    this.#value = value;
  }
  token(): string {
    return this.#value;
  }
}

/** A token pair with the absolute expiry the {@link TokenSource} computed. */
export interface StoredTokenPair extends TokenPair {
  /** Expiry of the access token in milliseconds since the epoch. */
  expires_at?: number;
}

/** Anything that can call `POST /v1/auth/token`, i.e. a {@link Client}. */
export interface TokenEndpoint {
  token(body: TokenRequest, options?: RequestOptions): Promise<TokenPair>;
}

export interface TokenSourceOptions {
  /** Refresh this long before the access token expires (default 30s, at most half its lifetime). */
  skewMs?: number;
  /**
   * Called with every new pair, e.g. to persist the rotated refresh token.
   * Store the whole pair: passing it back to the constructor restores the session.
   */
  onRefresh?: (pair: StoredTokenPair) => void | Promise<void>;
  /** Clock, for tests. */
  now?: () => number;
}

/**
 * Holds a Tenarium token pair and refreshes the access token with the
 * `refresh_token` grant shortly before it expires, and once when the server
 * rejects it with 401. Refreshes are serialized: concurrent callers share
 * one refresh, so a rotated refresh token is never reused (reusing one makes
 * the server revoke the session).
 *
 * ```ts
 * const pair = await client.token({ grant_type: "password", email, password });
 * const authed = client.with({ tokenSource: new TokenSource(client, pair) });
 * ```
 */
export class TokenSource implements TokenProvider {
  readonly #endpoint: TokenEndpoint;
  readonly #skewMs: number;
  readonly #onRefresh?: (pair: StoredTokenPair) => void | Promise<void>;
  readonly #now: () => number;
  #pair: StoredTokenPair;
  #inflight: Promise<string> | null = null;

  constructor(endpoint: TokenEndpoint, pair: TokenPair | StoredTokenPair, options: TokenSourceOptions = {}) {
    this.#endpoint = endpoint;
    this.#skewMs = options.skewMs ?? 30_000;
    this.#onRefresh = options.onRefresh;
    this.#now = options.now ?? Date.now;
    this.#pair = this.#stamp(pair);
  }

  /** The current token pair. */
  get pair(): StoredTokenPair {
    return { ...this.#pair };
  }

  /** Returns a valid access token, refreshing it first if it expires soon. */
  async token(): Promise<string> {
    if (this.#inflight) return this.#inflight;
    if (this.#pair.access_token && !this.#expiring()) return this.#pair.access_token;
    return this.#refresh();
  }

  /** Refreshes after the server rejected `rejected`, unless that already happened. */
  async reauth(rejected: string): Promise<string> {
    if (this.#inflight) return this.#inflight;
    if (this.#pair.access_token && this.#pair.access_token !== rejected) return this.#pair.access_token;
    return this.#refresh();
  }

  /** Forces a refresh now. */
  refresh(): Promise<string> {
    return this.#inflight ?? this.#refresh();
  }

  #expiring(): boolean {
    const exp = this.#pair.expires_at;
    if (!exp) return false;
    let skew = this.#skewMs;
    if (this.#pair.expires_in > 0) skew = Math.min(skew, (this.#pair.expires_in * 1000) / 2);
    return this.#now() + skew >= exp;
  }

  #stamp(pair: TokenPair | StoredTokenPair): StoredTokenPair {
    const p: StoredTokenPair = { ...pair };
    if (p.expires_at === undefined && p.expires_in > 0) p.expires_at = this.#now() + p.expires_in * 1000;
    return p;
  }

  #refresh(): Promise<string> {
    const run = async (): Promise<string> => {
      const refreshToken = this.#pair.refresh_token;
      if (!refreshToken) throw new Error("tenarium: access token expired and no refresh token is available");
      const next = await this.#endpoint.token({ grant_type: "refresh_token", refresh_token: refreshToken });
      this.#pair = this.#stamp({ ...next, expires_at: undefined });
      await this.#onRefresh?.(this.pair);
      return this.#pair.access_token;
    };
    const p = run().finally(() => {
      if (this.#inflight === p) this.#inflight = null;
    });
    this.#inflight = p;
    return p;
  }
}
