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

    confirmLogin: async ({ body, response, cookies }) => {
      const totpTemporaryJWT = ctx.cookieService.getTotpTemporary(cookies);
      if (!totpTemporaryJWT) {
        return { error: 'Login session expired. Please log in again.' }
      }
      const decoded = await ctx.cookieService.verifyTotpTemporary(cookies);
      if (!decoded) {
        return { error: 'Login session expired. Please log in again.' }
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
          return {error: 'Wrong or expired OTP code'}
        }
      }

      let verified = null;
      if (body.usePasskey && ctx.options.passkeys) {
        const cookiesValidationResult = await ctx.passkeyService.validateCookiesForPasskeyLogin(cookies);
        if (!cookiesValidationResult.ok) {
          return { error: cookiesValidationResult.error };
        }
        const res = await ctx.passkeyService.verifyPasskeyResponse(body.passkeyOptions, decoded.pk, cookiesValidationResult.decodedPasskeysCookies);
        if (res.ok && res.passkeyConfirmed) {
          verified = true;
        }
      } else {
        const verificationResult = await ctx.totpService.verifyUserCode(decoded.pk, body.code);
        verified = 'ok' in verificationResult && verificationResult.ok;
      }
      if (verified) {
        ctx.cookieService.removeTotpTemporary(response)
        ctx.cookieService.setAuthCookie({expireInDuration: decoded.sessionDuration, response, username:decoded.userName, pk:decoded.pk})
        return { status: 'ok', allowedLogin: true }
      } else {
        response.setStatus(403, "Wrong or expired TOTP code");
        return {error: 'Wrong or expired TOTP code', }
      }
    },

    confirmLoginWithPasskey: async ({ body, response, cookies, headers, requestUrl, query }) => {
      if ( ctx.options.passkeys.allowLoginWithPasskeys !== true ) {
        return { error: 'Login with passkeys is not allowed' };
      }

      const passkeyResponse = body.passkeyResponse;
      if (!passkeyResponse) {
        return { error: 'Passkey response is required' };
      }

      const passkeyLoginResult = await ctx.passkeyService.getLoginUserByPasskeyResponse(passkeyResponse, cookies);
      if (!passkeyLoginResult.ok) {
        return { error: passkeyLoginResult.error };
      }
      const user = passkeyLoginResult.user;
      const username = user[ctx.adminforth.config.auth.usernameField];

      const adminUser = {
        dbUser: user,
        pk: user.id,
        username,
      };

      const toReturn = { allowedLogin: true, error: '' };
      const rememberMe = body?.rememberMe || false;

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
        rememberMe ? ctx.adminforth.config.auth.rememberMeDuration || '30d' : '1d',
      );

      const rememberDaysAfterPasskeyLogin = (ctx.options.passkeys.rememberDaysAfterPasskeyLogin ? ctx.options.passkeys.rememberDaysAfterPasskeyLogin.toString().concat('d') : null);
      if ( toReturn.allowedLogin === true ) {
        ctx.cookieService.setAuthCookie({
          response,
          username,
          pk: user.id,
          expireInDuration: rememberDaysAfterPasskeyLogin ? rememberDaysAfterPasskeyLogin : ctx.adminforth.config.auth.rememberMeDuration,
        });
      }
      return toReturn;
    },

    skipAllow: async ({ cookies }) => {
      const decoded = await ctx.cookieService.verifyTotpTemporary(cookies);
      if (!decoded) {
        return { status: "error", message: "Invalid token" };
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

    verifyTotp: async ({ adminUser, body }) => {
      if (!body?.code) return { error: 'Code is required' };

      return ctx.totpService.verifyAdminUserCode(adminUser, body.code);
    },
  };
}
