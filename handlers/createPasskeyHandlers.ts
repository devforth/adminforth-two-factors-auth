import type { HttpExtra } from "adminforth";
import { errorMessage } from "../utils/errors.js";

export function createPasskeyHandlers(ctx: any) {
  return {
    registerPasskeyRequest: async ({ body, adminUser, response, cookies, headers }) => {
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
        return { ok: false, error: 'error' in verificationResult ? verificationResult.error : 'Verification failed' };
      }

      return ctx.passkeyService.createRegisterPasskeyRequest(mode, adminUser, response);
    },

    finishRegisteringPasskey: async ({ body, adminUser, cookies }) => {
      return ctx.passkeyService.finishRegisteringPasskey(body, adminUser, cookies);
    },

    createSignInRequest: async ({ response }) => {
      return ctx.passkeyService.createSignInRequest(response);
    },

    getPasskeys: async ({ adminUser }) => {
      return ctx.passkeyService.getPasskeys(adminUser);
    },

    deletePasskey: async ({ body, adminUser }) => {
      return ctx.passkeyService.deletePasskey(body.passkeyId, adminUser);
    },

    renamePasskey: async ({ body, adminUser }) => {
      return ctx.passkeyService.renamePasskey(body.passkeyId, body.newName, adminUser);
    },

    checkIfUserHasPasskeys: async ({ cookies }) => {
      return ctx.passkeyService.checkIfUserHasPasskeys(cookies);
    },

    resolveVerifyAuto: async ({ body, adminUser, response, cookies, headers }) => {
      const sessionsIds = body?.sessionsIds;
      const confirmationResult = body?.confirmationResult;
      const idsToResolve = Array.isArray(sessionsIds) ? sessionsIds : [];

      const resolveAllIdsAsFailed = (message) => {
        for (const id of idsToResolve) {
          ctx.autoVerify.resolveResponse(id, { ok: false, error: message });
        }
        return { ok: false, error: message };
      }

      try {
        if (!idsToResolve.length || !confirmationResult) {
          return(resolveAllIdsAsFailed('Confirmation window was closed or did not return required data'));
        }

        for (const id of idsToResolve) {
          const validationResult = await ctx.adminforth.auth.verify(id, 'auto2FA', false);
          if (!validationResult) {
            return(resolveAllIdsAsFailed('Invalid session ID or confirmation result'));
          }
          if (validationResult.adminUserPk !== adminUser.pk) {
            return(resolveAllIdsAsFailed('Session does not belong to the authenticated user'));
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
          return(resolveAllIdsAsFailed('Verification failed'));
        }
        if ('ok' in verificationResult && verificationResult.ok){
          for (const id of idsToResolve) {
            ctx.autoVerify.resolveResponse(id, { ok: true, passkeyConfirmed: verificationResult });
          }
          return { ok: true };
        }
        return(resolveAllIdsAsFailed('Verification failed'));
      } catch (error) {
        console.error('[AdminForth 2FA] Error resolving automatic 2FA verification', error);
        return(resolveAllIdsAsFailed(errorMessage(error)));
      }
    },
  };
}
