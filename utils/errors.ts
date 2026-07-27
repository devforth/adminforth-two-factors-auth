import type { IAdminForthHttpResponse } from "adminforth";
import type { ErrorResponse } from "./types.js";

export enum HttpStatus {
  BAD_REQUEST = 400,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  TOO_MANY_REQUESTS = 429,
  INTERNAL_SERVER_ERROR = 500,
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
