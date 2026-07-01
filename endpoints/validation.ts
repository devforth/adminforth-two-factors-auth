import { z } from "zod";

// twofa endpoints
export const confirmLoginBodySchema = z.object({
  code: z.string().optional(),
  skip: z.boolean().optional(),
  usePasskey: z.boolean().optional(),
  passkeyOptions: z.any().optional(),
}).strict();

export const confirmLoginWithPasskeyBodySchema = z.object({
  passkeyResponse: z.record(z.string(), z.any()),
  rememberMe: z.boolean().optional(),
}).strict();

export const verifyTotpBodySchema = z.object({
  code: z.string(),
}).strict();

// passkey endpoints
export const registrationOptionsBodySchema = z.object({
  mode: z.string().nullish(),
  confirmationResult: z.record(z.string(), z.any()),
}).strict();

export const finishRegistrationBodySchema = z.object({
  credential: z.any(),
  origin: z.string(),
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
  confirmationResult: z.record(z.string(), z.any()),
}).strict();
