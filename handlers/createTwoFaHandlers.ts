import { HttpStatus, respondWithStatus } from "../utils/errors.js";

export function createTwoFaHandlers(ctx: any) {
  return {
    initSetup: async ({ cookies }) => {
      const toReturn = {totpJWT:null,status:'ok',}
      const totpTemporaryJWT = ctx.cookieService.getTotpTemporary(cookies);
      if (totpTemporaryJWT){
        toReturn.totpJWT = totpTemporaryJWT
      }
      return toReturn
    },

    confirmLogin: async ({ body, response, cookies, headers }) => {
      if (!(await ctx.checkPasskeyLoginRateLimit(headers))) {
        return respondWithStatus({ error: 'Too many login attempts, please try again later' }, response, HttpStatus.TOO_MANY_REQUESTS);
      }

      const totpTemporaryJWT = ctx.cookieService.getTotpTemporary(cookies);
      if (!totpTemporaryJWT) {
        return respondWithStatus({ error: 'Login session expired. Please log in again.' }, response, HttpStatus.FORBIDDEN)
      }
      const decoded = await ctx.cookieService.verifyTotpTemporary(cookies);
      if (!decoded) {
        return respondWithStatus({ error: 'Login session expired. Please log in again.' }, response, HttpStatus.FORBIDDEN)
      }

      if (decoded.newSecret) {
        const verified = body.skip && decoded.userCanSkipSetup ? true : ctx.totpService.verifySecret(decoded.newSecret, body.code);
        if (verified) {
          if (!body.skip) {
            await ctx.totpService.saveSecret(decoded.pk, decoded.newSecret);
          }
          ctx.cookieService.removeTotpTemporary(response)
          ctx.cookieService.setAuthCookie({expireInDuration: decoded.sessionDuration, response, username:decoded.userName, pk:decoded.pk})
          return { status: 'ok', allowedLogin: true }
        } else {
          return respondWithStatus({ error: 'Wrong or expired OTP code' }, response, HttpStatus.FORBIDDEN)
        }
      }

      let verified = false;
      let verificationError = 'Wrong or expired OTP code';
      if (body.usePasskey && ctx.options.passkeys) {
        const cookiesValidationResult = await ctx.passkeyService.validateLoginChallengeCookie(cookies);
        if (!cookiesValidationResult.ok) {
          return respondWithStatus({ error: cookiesValidationResult.error }, response, HttpStatus.FORBIDDEN);
        }
        const res = await ctx.passkeyService.verifyPasskeyResponse(body.passkeyOptions, decoded.pk, cookiesValidationResult.decodedPasskeysCookies);
        if (res.ok && res.passkeyConfirmed) {
          verified = true;
        } else {
          verificationError = res.error ?? 'Invalid passkey';
        }
      } else {
        const verificationResult = await ctx.totpService.verifyUserCode(decoded.pk, body.code);
        verified = 'ok' in verificationResult && verificationResult.ok;
        if (!verified) {
          verificationError = verificationResult.error ?? verificationError;
        }
      }
      if (verified) {
        ctx.cookieService.removeTotpTemporary(response)
        ctx.cookieService.setAuthCookie({expireInDuration: decoded.sessionDuration, response, username:decoded.userName, pk:decoded.pk})
        return { status: 'ok', allowedLogin: true }
      } else {
        return respondWithStatus({ error: verificationError }, response, HttpStatus.FORBIDDEN)
      }
    },

    confirmLoginWithPasskey: async ({ body, response, cookies, headers, requestUrl, query }) => {
      if (!(await ctx.checkPasskeyLoginRateLimit(headers))) {
        return respondWithStatus({ error: 'Too many login attempts, please try again later' }, response, HttpStatus.TOO_MANY_REQUESTS);
      }

      if (!ctx.options.passkeys || ctx.options.passkeys.allowLoginWithPasskeys === false) {
        return respondWithStatus({ error: 'Login with passkeys is not allowed' }, response, HttpStatus.FORBIDDEN);
      }

      const passkeyResponse = body.passkeyResponse;
      if (!passkeyResponse) {
        return respondWithStatus({ error: 'Passkey response is required' }, response, HttpStatus.BAD_REQUEST);
      }

      const passkeyLoginResult = await ctx.passkeyService.getLoginUserByPasskeyResponse(passkeyResponse, cookies);
      if (!passkeyLoginResult.ok) {
        return respondWithStatus({ error: passkeyLoginResult.error }, response, HttpStatus.FORBIDDEN);
      }
      const user = passkeyLoginResult.user;
      const username = user[ctx.adminforth.config.auth.usernameField];
      const userPk = user[ctx.userRepository.getUserPkField()];

      const adminUser = {
        dbUser: user,
        pk: userPk,
        username,
      };

      const toReturn = { allowedLogin: true, error: '' };
      const rememberMe = body?.rememberMe || false;
      const rememberDaysAfterPasskeyLogin = ctx.options.passkeys.rememberDaysAfterPasskeyLogin
        ? ctx.options.passkeys.rememberDaysAfterPasskeyLogin.toString().concat('d')
        : null;
      const expireInDuration = rememberMe
        ? (rememberDaysAfterPasskeyLogin ?? ctx.adminforth.config.auth.rememberMeDuration ?? '30d')
        : '1d';

      await ctx.adminforth.restApi.processLoginCallbacks(
        adminUser,
        toReturn,
        response,
        {
          headers,
          cookies,
          requestUrl,
          query,
          body: {},
          response,
          meta: {
            loginAllowedByPasskeyDirectSignIn: true
          },
        },
        expireInDuration,
      );

      if ( toReturn.allowedLogin === true ) {
        ctx.cookieService.setAuthCookie({
          response,
          username,
          pk: userPk,
          expireInDuration,
        });
      }
      return toReturn;
    },

    skipAllow: async ({ cookies, response }) => {
      const decoded = await ctx.cookieService.verifyTotpTemporary(cookies);
      if (!decoded) {
        return respondWithStatus({ status: "error", message: "Invalid token" }, response, HttpStatus.FORBIDDEN);
      }
      if (!decoded.newSecret) {
        return { status: "ok", skipAllowed: false };
      } else {
        return {
          status: "ok",
          skipAllowed: decoded.userCanSkipSetup,
        };
      }
    },

    skipAllowModal: async ({ adminUser, headers, cookies }) => {
      if ( ctx.options.usersFilterToApply ) {
        const res = ctx.options.usersFilterToApply(adminUser);
        if ( res === false ) {
          return { skipAllowed: true };
        }
      }
      if ( ctx.options.usersFilterToAllowSkipSetup ) {
        const res = await ctx.checkIfSkipSetupAllowSkipVerify(adminUser);
        if ( res.skipAllowed === true ) {
          return { skipAllowed: true };
        }
      }

      if ( ctx.options.stepUpMfaGracePeriodSeconds ) {
        const verificationResult = await ctx.cookieService.isMfaGraceValid(headers, cookies, true);
        if ( verificationResult === true ) {
          return { skipAllowed: true };
        }
      }

      return { skipAllowed: false };
    },

    verifyTotp: async ({ adminUser, body, response }) => {
      if (!body?.code) return respondWithStatus({ error: 'Code is required' }, response, HttpStatus.BAD_REQUEST);

      const verificationResult = await ctx.totpService.verifyAdminUserCode(adminUser, body.code);
      if (!verificationResult.ok) {
        return respondWithStatus(verificationResult, response, HttpStatus.FORBIDDEN);
      }
      return verificationResult;
    },
  };
}
