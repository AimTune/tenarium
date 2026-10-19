/** Tenant lifecycle status. */
export type TenantStatus =
  | "provisioning"
  | "active"
  | "suspended"
  | "failed"
  | "deleting"
  | "deleted";

/** Tenant state with effective entitlements (plan plus tenant overrides). */
export interface Tenant {
  id: string;
  slug: string;
  name?: string;
  status: TenantStatus;
  plan?: string;
  parent_id?: string;
  labels?: Record<string, string>;
  features: Record<string, boolean>;
  limits: Record<string, number>;
  version?: number;
}

/** Claims of a verified Tenarium access token. */
export interface Claims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  tid?: string;
  email?: string;
  name?: string;
  roles?: string[];
  /** The tenant's region (tenant tokens), for routing. */
  region?: string;
  [claim: string]: unknown;
}

/** Whether feature is enabled for the tenant. */
export function hasFeature(tenant: Tenant | null | undefined, feature: string): boolean {
  return tenant?.features?.[feature] === true;
}

/** The limit for metric, or undefined when the metric is unlimited. */
export function limitOf(tenant: Tenant | null | undefined, metric: string): number | undefined {
  const v = tenant?.limits?.[metric];
  return typeof v === "number" ? v : undefined;
}

/** Error codes produced by the middleware. */
export type TenantErrorCode =
  | "tenant_required"
  | "tenant_not_found"
  | "tenant_inactive"
  | "tenant_mismatch"
  | "unauthorized"
  | "feature_disabled"
  | "quota_exceeded"
  | "tenant_unavailable";

const STATUS: Record<TenantErrorCode, number> = {
  tenant_required: 404,
  tenant_not_found: 404,
  tenant_inactive: 403,
  tenant_mismatch: 403,
  unauthorized: 401,
  feature_disabled: 403,
  quota_exceeded: 429,
  tenant_unavailable: 503,
};

/** A rejection with the HTTP status the middleware answers with. */
export class TenantError extends Error {
  readonly code: TenantErrorCode;
  readonly status: number;

  constructor(code: TenantErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "TenantError";
    this.code = code;
    this.status = STATUS[code];
  }

  /** The JSON body written by the adapters (Tenarium's error format). */
  toJSON(): { error: { code: string; message: string } } {
    const message = this.status === 503 ? "tenant state unavailable" : this.message;
    return { error: { code: this.code, message } };
  }
}

/** A non-2xx answer of the Tenarium API. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(`tenarium api: ${status} ${code}: ${message}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** Recording usage would exceed the tenant's limit (HTTP 429). */
export class QuotaExceededError extends ApiError {
  constructor(code: string, message: string) {
    super(429, code, message);
    this.name = "QuotaExceededError";
  }
}
