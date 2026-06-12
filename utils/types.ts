export type AnyRecord = Record<string, any>;

export type ErrorResponse = {
  ok: false;
  error: string;
};

export type OkResponse<T extends AnyRecord = AnyRecord> = {
  ok: true;
} & T;

export type PluginResponse<T extends AnyRecord = AnyRecord> = OkResponse<T> | ErrorResponse;
