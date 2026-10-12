import type { IAdminForthHttpResponse } from "adminforth";
import type { ErrorResponse } from "./types.js";

export enum HttpStatus {
  BAD_REQUEST = 400,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  TOO_MANY_REQUESTS = 429,
  INTERNAL_SERVER_ERROR = 500,
}

export enum TwoFactorErrorCode {
  REQUIRED = 'TWO_FACTOR_REQUIRED',
  INVALID = 'TWO_FACTOR_INVALID',
  RATE_LIMITED = 'TWO_FACTOR_RATE_LIMITED',
  NOT_SET_UP = 'TWO_FACTOR_NOT_SET_UP',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  UNSUPPORTED_MODE = 'UNSUPPORTED_CONFIRMATION_MODE',
  BROWSER_CONTEXT_REQUIRED = 'BROWSER_CONTEXT_REQUIRED',
  CANCELLED = 'VERIFICATION_CANCELLED',
  TIMEOUT = 'VERIFICATION_TIMEOUT',
  INVALID_SESSION = 'INVALID_VERIFICATION_SESSION',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}

export function respondWithStatus<T>(body: T, response: IAdminForthHttpResponse, status: HttpStatus): T {
  response.setStatus(status);
  return body;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function errorResult(message: string): ErrorResponse {
  return { ok: false, error: message };
}

export function prefixedErrorResult(prefix: string, error: unknown): ErrorResponse {
  return errorResult(`${prefix}${errorMessage(error)}`);
}
