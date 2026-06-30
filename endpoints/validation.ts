import { z } from "zod";

export function parseBody<T>(
  schema: z.ZodType<T>,
  body: unknown,
  response: { setStatus: (code: number, message: string) => void },
): { ok: true; data: T } | { ok: false; error: { error: string; details: unknown } } {
  const parsed = schema.safeParse(body ?? {});
  if (!parsed.success) {
    response.setStatus(400, '');
    return {
      ok: false,
      error: { error: 'Request body validation failed', details: parsed.error.issues },
    };
  }
  return { ok: true, data: parsed.data };
}

// twofa endpoints
export const confirmLoginBodySchema = z.object({
  code: z.string().optional(),
  skip: z.boolean().optional(),
  usePasskey: z.boolean().optional(),
  passkeyOptions: z.any().optional(),
}).strict();

export const confirmLoginWithPasskeyBodySchema = z.object({
  passkeyResponse: z.any().optional(),
  rememberMe: z.boolean().optional(),
}).strict();

export const verifyTotpBodySchema = z.object({
  code: z.string(),
}).strict();

// passkey endpoints
export const registrationOptionsBodySchema = z.object({
  mode: z.string().nullish(),
  confirmationResult: z.any().optional(),
}).strict();

export const finishRegistrationBodySchema = z.object({
  credential: z.any(),
  origin: z.string().optional(),
}).strict();

export const deletePasskeyBodySchema = z.object({
  passkeyId: z.string(),
}).strict();

export const renamePasskeyBodySchema = z.object({
  passkeyId: z.string(),
  newName: z.string(),
}).strict();

export const resolveVerifyAutoBodySchema = z.object({
  sessionsIds: z.array(z.string()).nullish(),
  confirmationResult: z.any().optional(),
}).strict();
