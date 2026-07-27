import type { HttpExtra } from "adminforth";
import { HttpStatus, errorMessage, respondWithStatus } from "../utils/errors.js";

export function createPasskeyHandlers(ctx: any) {
  return {
    createRegistrationOptions: async ({ body, adminUser, response, cookies, headers }) => {
      const mode = body?.mode;

      const confirmationResult = body?.confirmationResult;
      const verificationResult = await ctx.verifyMfaConfirmation(confirmationResult, {
        adminUser: adminUser,
        userPk: adminUser.pk,
        cookies: cookies,
        response: response,
        extra: {
          headers,
        } as HttpExtra
      });
      if (!verificationResult || !('ok' in verificationResult)) {
        return respondWithStatus(
          { ok: false, error: 'error' in verificationResult ? verificationResult.error : 'Verification failed' },
          response,
          HttpStatus.FORBIDDEN,
        );
      }

      const registrationOptions = await ctx.passkeyService.createRegistrationOptions(mode, adminUser, response);
      if (!registrationOptions.ok) {
        return respondWithStatus(registrationOptions, response, HttpStatus.NOT_FOUND);
      }
      return registrationOptions;
    },

    finishRegistration: async ({ body, adminUser, cookies, response }) => {
      const registrationResult = await ctx.passkeyService.finishRegistration(body, adminUser, cookies);
      if (!registrationResult.ok) {
        return respondWithStatus(registrationResult, response, HttpStatus.FORBIDDEN);
      }
      return registrationResult;
    },

    createLoginOptions: async ({ response, headers }) => {
      if (!(await ctx.checkPasskeyLoginRateLimit(headers))) {
        return respondWithStatus({ error: 'Too many login attempts, please try again later' }, response, HttpStatus.TOO_MANY_REQUESTS);
      }
      const loginOptions = await ctx.passkeyService.createLoginOptions(response);
      if (!loginOptions.ok) {
        return respondWithStatus(loginOptions, response, HttpStatus.INTERNAL_SERVER_ERROR);
      }
      return loginOptions;
    },

    getPasskeys: async ({ adminUser }) => {
      return ctx.passkeyService.getPasskeys(adminUser);
    },

    deletePasskey: async ({ body, adminUser, response }) => {
      const deleteResult = await ctx.passkeyService.deletePasskey(body.passkeyId, adminUser);
      if (!deleteResult.ok) {
        return respondWithStatus(deleteResult, response, HttpStatus.NOT_FOUND);
      }
      return deleteResult;
    },

    renamePasskey: async ({ body, adminUser, response }) => {
      const renameResult = await ctx.passkeyService.renamePasskey(body.passkeyId, body.newName, adminUser);
      if (!renameResult.ok) {
        return respondWithStatus(renameResult, response, HttpStatus.NOT_FOUND);
      }
      return renameResult;
    },

    checkIfUserHasPasskeys: async ({ cookies, response }) => {
      const checkResult = await ctx.passkeyService.checkIfUserHasPasskeys(cookies);
      if (checkResult.error) {
        return respondWithStatus(checkResult, response, HttpStatus.FORBIDDEN);
      }
      return checkResult;
    },

    resolveVerifyAuto: async ({ body, adminUser, response, cookies, headers }) => {
      const sessionsIds = body?.sessionsIds;
      const confirmationResult = body?.confirmationResult;
      const idsToResolve = Array.isArray(sessionsIds) ? sessionsIds : [];

      const resolveAllIdsAsFailed = (message, code?: string) => {
        const payload = code ? { ok: false, code, error: message } : { ok: false, error: message };
        for (const id of idsToResolve) {
          ctx.autoVerify.resolveResponse(id, payload);
        }
        return payload;
      }

      try {
        if (!idsToResolve.length || !confirmationResult) {
          return respondWithStatus(
            resolveAllIdsAsFailed('Confirmation window was closed', 'VERIFICATION_CANCELLED'),
            response,
            HttpStatus.BAD_REQUEST,
          );
        }

        for (const id of idsToResolve) {
          const validationResult = await ctx.adminforth.auth.verify(id, 'auto2FA', false);
          if (!validationResult) {
            return respondWithStatus(resolveAllIdsAsFailed('Invalid session ID or confirmation result'), response, HttpStatus.FORBIDDEN);
          }
          if (validationResult.adminUserPk !== adminUser.pk) {
            return respondWithStatus(resolveAllIdsAsFailed('Session does not belong to the authenticated user'), response, HttpStatus.FORBIDDEN);
          }
        }

        const verificationResult = await ctx.verifyMfaConfirmation(confirmationResult, {
          adminUser: adminUser,
          userPk: adminUser.pk,
          cookies: cookies,
          response: response,
          extra: {
            headers: headers,
          } as HttpExtra
        });
        if ( !verificationResult || !('ok' in verificationResult) ) {
          return respondWithStatus(resolveAllIdsAsFailed(verificationResult?.error ?? 'Verification failed'), response, HttpStatus.FORBIDDEN);
        }
        if ('ok' in verificationResult && verificationResult.ok){
          for (const id of idsToResolve) {
            ctx.autoVerify.resolveResponse(id, { ok: true, passkeyConfirmed: verificationResult });
          }
          return { ok: true };
        }
        return respondWithStatus(resolveAllIdsAsFailed('Verification failed'), response, HttpStatus.FORBIDDEN);
      } catch (error) {
        console.error('[AdminForth 2FA] Error resolving automatic 2FA verification', error);
        return respondWithStatus(resolveAllIdsAsFailed(errorMessage(error)), response, HttpStatus.INTERNAL_SERVER_ERROR);
      }
    },
  };
}
