/** Fields of a {@link TenariumError}. */
export interface TenariumErrorInit {
  status: number;
  code: string;
  message: string;
  field?: string;
  requestId?: string;
  retryAfterMs?: number;
  body?: unknown;
}

/**
 * A non-2xx API response. The server reports errors as
 * `{"error": {"code", "message", "field"}}`; SCIM endpoints use SCIM error
 * bodies, whose `scimType` and `detail` become `code` and `message`.
 */
export class TenariumError extends Error {
  /** HTTP status code. */
  readonly status: number;
  /** Machine-readable code, e.g. `not_found`, `version_conflict`, `quota_exceeded`. */
  readonly code: string;
  /** The offending input field or, for quota errors, the metric. */
  readonly field?: string;
  /** The server's `X-Request-ID`, useful when reporting issues. */
  readonly requestId?: string;
  /** The server's `Retry-After` hint in milliseconds. */
  readonly retryAfterMs?: number;
  /** The decoded response body. */
  readonly body?: unknown;

  constructor(init: TenariumErrorInit) {
    super(init.message);
    this.name = "TenariumError";
    this.status = init.status;
    this.code = init.code;
    if (init.field) this.field = init.field;
    if (init.requestId) this.requestId = init.requestId;
    if (init.retryAfterMs !== undefined) this.retryAfterMs = init.retryAfterMs;
    if (init.body !== undefined) this.body = init.body;
  }

  /** E.g. `TenariumError: 404 not_found: tenant not found (field id) [request 42]`. */
  override toString(): string {
    let s = `${this.name}: ${this.status}`;
    if (this.code) s += ` ${this.code}`;
    if (this.message) s += `: ${this.message}`;
    if (this.field) s += ` (field ${this.field})`;
    if (this.requestId) s += ` [request ${this.requestId}]`;
    return s;
  }
}

function hasStatus(err: unknown, status: number): boolean {
  return err instanceof TenariumError && err.status === status;
}

function hasCode(err: unknown, code: string): boolean {
  return err instanceof TenariumError && err.code === code;
}

/** A 404 response. */
export const isNotFound = (err: unknown): err is TenariumError => hasStatus(err, 404);
/** A 409 response (already exists, invalid transition). */
export const isConflict = (err: unknown): err is TenariumError => hasStatus(err, 409);
/** A 412 response: the resource changed since the version sent as `ifMatch`. */
export const isVersionConflict = (err: unknown): err is TenariumError => hasStatus(err, 412);
/** A refused usage increment; `field` is the metric. */
export const isQuotaExceeded = (err: unknown): err is TenariumError => hasCode(err, "quota_exceeded");
/** A 403 response. */
export const isForbidden = (err: unknown): err is TenariumError => hasStatus(err, 403);
/** A 401 response (missing, invalid or expired credentials). */
export const isUnauthorized = (err: unknown): err is TenariumError => hasStatus(err, 401);
/** A 400 `validation_failed` response. */
export const isValidation = (err: unknown): err is TenariumError => hasCode(err, "validation_failed");

/** Builds the error for a non-2xx response from its status, headers and body text. */
export function parseError(status: number, headers: Headers, text: string): TenariumError {
  const requestId = headers.get("x-request-id") ?? undefined;
  const retryAfterMs = parseRetryAfter(headers.get("retry-after"));
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (body && typeof body === "object") {
    const e = (body as { error?: unknown }).error;
    if (e && typeof e === "object" && typeof (e as { code?: unknown }).code === "string") {
      const { code, message, field } = e as { code: string; message?: unknown; field?: unknown };
      return new TenariumError({
        status, code, message: typeof message === "string" ? message : "",
        field: typeof field === "string" ? field : undefined, requestId, retryAfterMs, body,
      });
    }
    const scim = body as { detail?: unknown; scimType?: unknown };
    if (typeof scim.detail === "string") {
      return new TenariumError({
        status, code: typeof scim.scimType === "string" ? scim.scimType : "", message: scim.detail,
        requestId, retryAfterMs, body,
      });
    }
  }
  let message = text.trim();
  if (message.length > 200) message = message.slice(0, 200) + "...";
  return new TenariumError({ status, code: "", message: message || `HTTP ${status}`, requestId, retryAfterMs, body });
}

/** Parses `Retry-After` (seconds or an HTTP date) into milliseconds. */
export function parseRetryAfter(v: string | null, now = Date.now()): number | undefined {
  if (!v) return undefined;
  if (/^\d+$/.test(v.trim())) return Number(v.trim()) * 1000;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : Math.max(t - now, 0);
}
