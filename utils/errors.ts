import type { ErrorResponse } from "./types.js";

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function errorResult(message: string): ErrorResponse {
  return { ok: false, error: message };
}

export function prefixedErrorResult(prefix: string, error: unknown): ErrorResponse {
  return errorResult(`${prefix}${errorMessage(error)}`);
}
