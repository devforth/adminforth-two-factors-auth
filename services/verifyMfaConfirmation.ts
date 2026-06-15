import type { AdminUser, HttpExtra, IAdminForthHttpResponse } from "adminforth";

export type VerifyOptions = {
  adminUser?: AdminUser;
  userPk?: string;
  cookies?: any;
  response?: IAdminForthHttpResponse;
  extra?: HttpExtra;
};

export async function verifyMfaConfirmation(
  ctx: any,
  confirmationResult: Record<string, any>,
  opts?: VerifyOptions,
): Promise<{ ok: true } | { error: string }> {
  if (!confirmationResult) return { error: "Confirmation result is required" };
  if (!opts?.adminUser) return { error: "Admin user is required" };
  if (!opts.userPk) return { error: "User PK is required" };

  const cookies = opts.extra?.cookies || opts.cookies;
  const response = opts.extra?.response || opts.response;

  if (ctx.options.usersFilterToApply) {
    const res = ctx.options.usersFilterToApply(opts.adminUser);
    if ( res === false ) {
      return { ok: true };
    }
  }
  if (ctx.options.usersFilterToAllowSkipSetup) {
    const res = await ctx.checkIfSkipSetupAllowSkipVerify(opts.adminUser);
    if ( res.skipAllowed === true ) {
      return { ok: true };
    }
  }
  if ( ctx.options.stepUpMfaGracePeriodSeconds && opts.extra?.headers && !confirmationResult.mode) {
    const verificationResult = await ctx.cookieService.isMfaGraceValid(opts.extra.headers, cookies);
    if ( verificationResult === true ) {
      return { ok: true };
    }
  }

  if (confirmationResult.mode === "totp") {
    const code = confirmationResult.result;
    const pk = opts?.userPk ?? ctx.userRepository.getUserPk(opts.adminUser);
    if (!pk) return { error: "User PK is required" };

    const verificationResult = await ctx.totpService.verifyUserCode(pk, code);

    if ( 'ok' in verificationResult && verificationResult.ok ) {
      if (ctx.options.stepUpMfaGracePeriodSeconds) {
        ctx.cookieService.issueMfaGrace({ headers: opts.extra?.headers, response }, cookies);
      }
      return { ok: true }
    }
    return verificationResult;
  } else if (confirmationResult.mode === "passkey") {
    const cookiesValidationResult = await ctx.passkeyService.validateLoginChallengeCookie(cookies);
    if (!cookiesValidationResult.ok) {
      return { error: cookiesValidationResult.error };
    }
    const verificationResult = await ctx.passkeyService.verifyPasskeyResponse(confirmationResult.result, opts.userPk, cookiesValidationResult.decodedPasskeysCookies );

    if (verificationResult.ok && verificationResult.passkeyConfirmed) {
      if (ctx.options.stepUpMfaGracePeriodSeconds) {
        ctx.cookieService.issueMfaGrace({ headers: opts.extra?.headers, response }, cookies);
      }
      return  { ok: true }
    }
    return { error: "Invalid passkey" }
  }
  return { error: "Unsupported confirmation mode" };
}
