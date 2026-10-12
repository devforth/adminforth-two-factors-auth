import { AsyncLocalStorage } from 'node:async_hooks';
import type { AdminUser, HttpExtra } from 'adminforth';
import type { MfaConfirmationResult } from './verifyMfaConfirmation.js';
import type { VerificationFailure, VerificationResult } from '../utils/types.js';

type Context = {
  confirmationResult: MfaConfirmationResult | undefined;
  extra: HttpExtra;
  results: Map<string, Promise<VerificationResult>>;
};

type ContextualVerificationFailure = VerificationFailure & { actionDescription?: string };

class MfaVerificationError extends Error {
  constructor(readonly result: ContextualVerificationFailure) {
    super(result.error);
  }
}

/** Keeps verification within one external request, including every CRUD hook it invokes. */
export class MfaRequestContext {
  private readonly storage = new AsyncLocalStorage<Context>();

  run<T>(confirmationResult: MfaConfirmationResult | undefined, extra: HttpExtra, callback: () => Promise<T>): Promise<T | ContextualVerificationFailure> {
    return this.storage.run({ confirmationResult, extra, results: new Map() }, async () => {
      try {
        return await callback();
      } catch (error) {
        if (error instanceof MfaVerificationError) return error.result;
        throw error;
      }
    });
  }

  async verify(
    adminUser: AdminUser,
    actionDescription: string | undefined,
    verifier: (confirmationResult: MfaConfirmationResult | undefined, extra: HttpExtra) => Promise<VerificationResult>,
  ): Promise<VerificationResult | undefined> {
    const context = this.storage.getStore();
    if (!context) return undefined;
    let result = context.results.get(adminUser.pk!);
    if (!result) {
      result = verifier(context.confirmationResult, context.extra);
      context.results.set(adminUser.pk!, result);
    }
    const verified = await result;
    if ('error' in verified) throw new MfaVerificationError({ ...verified, actionDescription });
    return verified;
  }
}
