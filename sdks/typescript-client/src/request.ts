// Types shared by the generated operations and the hand-written client.

/** Options accepted by every API call (the last argument of each method). */
export interface RequestOptions {
  /**
   * Make an update conditional on the resource version: a number (the
   * resource's `version`) or an ETag such as `"3"`. A stale version fails
   * with 412 (see {@link isVersionConflict}).
   */
  ifMatch?: string | number;
  /**
   * Sent as `Idempotency-Key`. The server replays the first response for a
   * repeated key, which makes the POST safe to retry.
   */
  idempotencyKey?: string;
  /** Extra request headers for this call. */
  headers?: Record<string, string>;
  /** Aborts the call, including retries and backoff waits. */
  signal?: AbortSignal;
  /** Per-attempt timeout in milliseconds; overrides the client's `timeoutMs`. */
  timeoutMs?: number;
}

/** One API request, as the generated operations describe it. */
export interface OperationRequest {
  method: string;
  /** Path template, e.g. `/v1/tenants/{id}`. */
  path: string;
  /** Values for the placeholders of `path`; they are URL-encoded. */
  pathParams?: Record<string, string | number>;
  /** Query parameters; arrays repeat the key, `undefined` values are skipped. */
  query?: object;
  body?: unknown;
  /** Media type of `body`; JSON and form bodies are encoded, others are sent as given. */
  contentType?: string;
  /** The operation needs no credentials (`security: []`), so none are sent. */
  public?: boolean;
  /** Creates get an automatic Idempotency-Key when retries are enabled. */
  autoIdempotencyKey?: boolean;
  options?: RequestOptions;
}

/** A page of a cursor-paginated list. */
export interface Page<T> {
  items?: T[];
  /** Cursor of the following page; absent on the last page. */
  next?: string;
}
