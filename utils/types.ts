import type { HttpExtra } from "adminforth";

export type AnyRecord = Record<string, any>;
export type CookieList = HttpExtra["cookies"];
export type HttpHeaders = HttpExtra["headers"];

export type ErrorResponse = {
  ok: false;
  code?: string;
  error: string;
};

export type OkResponse<T extends AnyRecord = AnyRecord> = {
  ok: true;
} & T;

export type PluginResponse<T extends AnyRecord = AnyRecord> = OkResponse<T> | ErrorResponse;
