export { Client, collect, etagOf, responseOf, type ClientOptions, type ResponseMeta } from "./client.ts";
export { StaticToken, TokenSource, type StoredTokenPair, type TokenEndpoint, type TokenProvider, type TokenSourceOptions } from "./auth.ts";
export {
  TenariumError,
  isConflict,
  isForbidden,
  isNotFound,
  isQuotaExceeded,
  isUnauthorized,
  isValidation,
  isVersionConflict,
  type TenariumErrorInit,
} from "./errors.ts";
export type { OperationRequest, Page, RequestOptions } from "./request.ts";
export { Operations } from "./generated/operations.ts";
export type * from "./generated/types.ts";
