import { StaticToken, TokenSource, type StoredTokenPair, type TokenProvider, type TokenSourceOptions } from "./auth.ts";
import { parseError } from "./errors.ts";
import { Operations } from "./generated/operations.ts";
import type { TokenPair } from "./generated/types.ts";
import type { OperationRequest, Page, RequestOptions } from "./request.ts";

/** Options of a {@link Client}. */
export interface ClientOptions {
  /** Server URL, e.g. `https://tenarium.example.com` (a path prefix is kept). */
  baseUrl: string;
  /** A static API key (`tnr_...`), sent as a bearer token. */
  apiKey?: string;
  /** A fixed bearer token, e.g. an access token from an external identity provider. */
  token?: string;
  /** Tokens from a provider; a {@link TokenSource} refreshes Tenarium sessions. */
  tokenSource?: TokenProvider;
  /**
   * Retry failed requests up to this many additional times (default 0).
   * Only requests that are safe to repeat are retried: GET, HEAD, PUT,
   * DELETE, OPTIONS, and POSTs that carry an Idempotency-Key. With retries
   * enabled, create calls get an Idempotency-Key automatically.
   */
  maxRetries?: number;
  /** First backoff delay in milliseconds; it doubles per attempt, with jitter (default 200). */
  retryBackoffMs?: number;
  /** Upper bound of the computed backoff in milliseconds (default 30000). */
  maxRetryDelayMs?: number;
  /** Per-attempt timeout in milliseconds (default none). */
  timeoutMs?: number;
  /** Headers sent with every request, e.g. `User-Agent` in Node.js. */
  headers?: Record<string, string>;
  /** The fetch implementation (default `globalThis.fetch`). */
  fetch?: typeof fetch;
}

/** Status and headers of the response a result was decoded from. */
export interface ResponseMeta {
  status: number;
  headers: Headers;
  /** The `ETag` header, e.g. `"3"`; pass it as `ifMatch`. */
  etag?: string;
  /** The `X-Request-ID` header. */
  requestId?: string;
}

const META: unique symbol = Symbol("tenarium.response");

/** Returns the response metadata of an object returned by a client method. */
export function responseOf(result: unknown): ResponseMeta | undefined {
  return result !== null && typeof result === "object" ? (result as { [META]?: ResponseMeta })[META] : undefined;
}

/** Returns the `ETag` of the response an object was decoded from. */
export function etagOf(result: unknown): string | undefined {
  return responseOf(result)?.etag;
}

const IDEMPOTENT = new Set(["GET", "HEAD", "PUT", "DELETE", "OPTIONS"]);

class TimeoutError extends Error {
  constructor(ms: number) {
    super(`tenarium: request timed out after ${ms}ms`);
    this.name = "TimeoutError";
  }
}

interface RawResponse {
  status: number;
  headers: Headers;
  text: string;
}

/**
 * Client for the Tenarium REST API. It has one method per operation of the
 * OpenAPI spec (see {@link Operations}), named after the operationId, plus
 * `<operation>All` async iterators for paginated lists.
 *
 * ```ts
 * const c = new Client({ baseUrl: "https://tenarium.example.com", apiKey, maxRetries: 3 });
 * const t = await c.createTenant({ slug: "acme", name: "Acme" });
 * for await (const t of c.listTenantsAll({ status: "active" })) console.log(t.slug);
 * ```
 *
 * A client holds no global state and can be shared.
 */
export class Client extends Operations {
  /** The server URL without a trailing slash. */
  readonly baseUrl: string;
  readonly #options: ClientOptions;
  readonly #tokens?: TokenProvider;
  readonly #fetch: typeof fetch;

  constructor(options: ClientOptions) {
    super();
    let url: URL;
    try {
      url = new URL(options.baseUrl);
    } catch {
      throw new TypeError(`tenarium: invalid base URL ${JSON.stringify(options.baseUrl)}`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new TypeError(`tenarium: invalid base URL ${JSON.stringify(options.baseUrl)}: want http(s)://host[:port]`);
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#options = { ...options };
    this.#tokens = options.tokenSource ?? (options.apiKey ?? options.token ? new StaticToken((options.apiKey ?? options.token)!) : undefined);
    const f = options.fetch ?? globalThis.fetch;
    if (typeof f !== "function") throw new TypeError("tenarium: no fetch implementation; pass options.fetch");
    this.#fetch = f.bind(globalThis);
  }

  /**
   * Returns a client with some options replaced, e.g. other credentials
   * after a login: `client.with({ tokenSource })`. Setting one kind of
   * credentials drops the others.
   */
  with(overrides: Partial<ClientOptions>): Client {
    const next: ClientOptions = { ...this.#options };
    if ("apiKey" in overrides || "token" in overrides || "tokenSource" in overrides) {
      delete next.apiKey;
      delete next.token;
      delete next.tokenSource;
    }
    return new Client({ ...next, ...overrides });
  }

  /**
   * Returns a {@link TokenSource} that refreshes `pair` through this client,
   * for use as `tokenSource`.
   */
  tokenSource(pair: TokenPair | StoredTokenPair, options?: TokenSourceOptions): TokenSource {
    return new TokenSource(this, pair, options);
  }

  /**
   * Calls any endpoint, e.g. one without an operationId such as `/readyz`.
   * The response is decoded like the typed methods' responses.
   */
  call<T = unknown>(
    method: string,
    path: string,
    init: Omit<OperationRequest, "method" | "path"> = {},
  ): Promise<T> {
    return this.request<T>({ ...init, method: method.toUpperCase(), path });
  }

  protected async request<T>(req: OperationRequest): Promise<T> {
    const opts: RequestOptions = req.options ?? {};
    const method = req.method;
    const url = this.baseUrl + expandPath(req.path, req.pathParams) + encodeQuery(req.query);
    const maxRetries = Math.max(0, this.#options.maxRetries ?? 0);

    const headers: Record<string, string> = { Accept: "application/json" };
    let body: string | undefined | BodyInit;
    if (req.body !== undefined) {
      const ct = req.contentType ?? "application/json";
      headers["Content-Type"] = ct;
      body = encodeBody(req.body, ct);
    }
    let idemKey = opts.idempotencyKey;
    if (idemKey === undefined && req.autoIdempotencyKey && maxRetries > 0) idemKey = newIdempotencyKey();
    if (idemKey !== undefined) headers["Idempotency-Key"] = idemKey;
    if (opts.ifMatch !== undefined) headers["If-Match"] = formatIfMatch(opts.ifMatch);
    Object.assign(headers, this.#options.headers, opts.headers);

    const retryable = IDEMPOTENT.has(method) || (method === "POST" && idemKey !== undefined);
    const tokens = req.public ? undefined : this.#tokens;
    let reauthed = false;

    for (let attempt = 0; ; attempt++) {
      let token: string | undefined;
      if (tokens) {
        token = await tokens.token();
        if (token) headers["Authorization"] = `Bearer ${token}`;
      }
      let res: RawResponse;
      try {
        res = await this.#send(url, { method, headers: { ...headers }, body }, opts);
      } catch (err) {
        if (opts.signal?.aborted) throw err;
        if (retryable && attempt < maxRetries) {
          await sleep(this.#backoff(attempt), opts.signal);
          continue;
        }
        throw err;
      }
      if (res.status === 401 && !reauthed && token && tokens?.reauth) {
        reauthed = true;
        try {
          await tokens.reauth(token);
          attempt--; // a credential refresh is not a retry
          continue;
        } catch {
          // fall through and report the 401
        }
      }
      if (res.status >= 400) {
        const err = parseError(res.status, res.headers, res.text);
        if (retryable && attempt < maxRetries && retryableStatus(res.status, err.retryAfterMs)) {
          await sleep(this.#backoff(attempt, err.retryAfterMs), opts.signal);
          continue;
        }
        throw err;
      }
      return decode(res) as T;
    }
  }

  protected async *paginate<T>(fetchPage: (cursor: string | undefined) => Promise<Page<T>>): AsyncIterableIterator<T> {
    let cursor: string | undefined;
    for (;;) {
      const page = await fetchPage(cursor);
      for (const item of page.items ?? []) yield item;
      const next = page.next;
      if (!next || next === cursor) return;
      cursor = next;
    }
  }

  async #send(url: string, init: RequestInit, opts: RequestOptions): Promise<RawResponse> {
    const timeoutMs = opts.timeoutMs ?? this.#options.timeoutMs;
    const outer = opts.signal;
    if (outer?.aborted) throw outer.reason;
    const ctrl = new AbortController();
    const onAbort = () => ctrl.abort(outer?.reason);
    outer?.addEventListener("abort", onAbort, { once: true });
    const timer = timeoutMs && timeoutMs > 0 ? setTimeout(() => ctrl.abort(new TimeoutError(timeoutMs)), timeoutMs) : undefined;
    try {
      const res = await this.#fetch(url, { ...init, signal: ctrl.signal });
      const text = await res.text();
      return { status: res.status, headers: res.headers, text };
    } catch (err) {
      // fetch rejects with an AbortError; report the reason instead.
      if (ctrl.signal.aborted && ctrl.signal.reason !== undefined) throw ctrl.signal.reason;
      throw err;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      outer?.removeEventListener("abort", onAbort);
    }
  }

  #backoff(attempt: number, retryAfterMs?: number): number {
    if (retryAfterMs !== undefined && retryAfterMs > 0) return retryAfterMs;
    const cap = this.#options.maxRetryDelayMs ?? 30_000;
    let d = (this.#options.retryBackoffMs ?? 200) * 2 ** Math.min(attempt, 16);
    if (!(d > 0) || d > cap) d = cap;
    return d / 2 + Math.random() * (d / 2);
  }
}

/** Drains an async iterator into an array. */
export async function collect<T>(items: AsyncIterable<T>, max = Infinity): Promise<T[]> {
  const out: T[] = [];
  if (max <= 0) return out;
  for await (const item of items) {
    out.push(item);
    if (out.length >= max) break;
  }
  return out;
}

function retryableStatus(status: number, retryAfterMs: number | undefined): boolean {
  if (status === 502 || status === 503 || status === 504) return true;
  return status === 429 && retryAfterMs !== undefined && retryAfterMs > 0;
}

function decode(res: RawResponse): unknown {
  if (res.status === 204 || res.text === "") return undefined;
  const ct = res.headers.get("content-type") ?? "";
  if (!/[/+]json\b/i.test(ct)) return res.text;
  const value: unknown = JSON.parse(res.text);
  if (value !== null && typeof value === "object") {
    const meta: ResponseMeta = { status: res.status, headers: res.headers };
    const etag = res.headers.get("etag");
    const requestId = res.headers.get("x-request-id");
    if (etag) meta.etag = etag;
    if (requestId) meta.requestId = requestId;
    Object.defineProperty(value, META, { value: meta, enumerable: false });
  }
  return value;
}

function expandPath(template: string, params: Record<string, string | number> = {}): string {
  return template.replace(/\{([^}]+)\}/g, (_, name: string) => {
    const v = params[name];
    if (v === undefined || v === null || v === "") throw new TypeError(`tenarium: empty path parameter ${name}`);
    return encodeURIComponent(String(v));
  });
}

function queryValue(v: unknown): string {
  if (v instanceof Date) return v.toISOString();
  return String(v);
}

function encodeQuery(query: object | undefined): string {
  if (!query) return "";
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      for (const x of v) if (x !== undefined && x !== null) q.append(k, queryValue(x));
    } else {
      q.append(k, queryValue(v));
    }
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

function encodeBody(body: unknown, contentType: string): BodyInit {
  if (/[/+]json\b/i.test(contentType)) return JSON.stringify(body);
  if (/^application\/x-www-form-urlencoded\b/i.test(contentType) && body !== null && typeof body === "object" && !(body instanceof URLSearchParams)) {
    return encodeQuery(body).replace(/^\?/, "");
  }
  return body as BodyInit;
}

function formatIfMatch(v: string | number): string {
  if (typeof v === "number") return `"${v}"`;
  return /^(W\/)?".*"$/.test(v) || v === "*" ? v : `"${v}"`;
}

function newIdempotencyKey(): string {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  const bytes = new Uint8Array(16);
  if (c?.getRandomValues) c.getRandomValues(bytes);
  else for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
