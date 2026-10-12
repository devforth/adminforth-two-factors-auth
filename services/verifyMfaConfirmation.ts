import type { AdminUser, HttpExtra, IAdminForthHttpResponse } from "adminforth";
import { TwoFactorErrorCode } from "../utils/errors.js";
import type { CookieList, VerificationResult } from "../utils/types.js";

type TotpConfirmationResult = {
  mode: "totp";
  result: string;
};

type PasskeyConfirmationResult = {
  mode: "passkey";
  result: {
    response: string;
    origin: string;
  };
};

type GraceConfirmationResult = {
  mode?: undefined;
};

export type MfaConfirmationResult = TotpConfirmationResult | PasskeyConfirmationResult | GraceConfirmationResult;

export type VerifyOptions = {
  adminUser: AdminUser;
  userPk: string;
  cookies?: CookieList;
  response?: IAdminForthHttpResponse;
  extra?: HttpExtra;
};

export async function verifyMfaConfirmation(
  ctx: any,
  confirmationResult: MfaConfirmationResult | undefined,
  opts: VerifyOptions,
): Promise<VerificationResult> {
  const mode = confirmationResult?.mode;
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
  if ( ctx.options.stepUpMfaGracePeriodSeconds && opts.extra?.headers && !mode) {
    const verificationResult = await ctx.cookieService.isMfaGraceValid(opts.extra.headers, cookies);
    if ( verificationResult === true ) {
      return { ok: true };
    }
  }
  if (!mode) {
    return { error: "Confirmation result is required", code: TwoFactorErrorCode.REQUIRED };
  }

  if (mode === "totp") {
    const { result: code } = confirmationResult as TotpConfirmationResult;
    const verificationResult = await ctx.totpService.verifyUserCode(opts.userPk, code);

    if ( 'ok' in verificationResult && verificationResult.ok ) {
      if (ctx.options.stepUpMfaGracePeriodSeconds) {
        ctx.cookieService.issueMfaGrace({ headers: opts.extra?.headers, response }, cookies);
      }
      return { ok: true }
    }
    return verificationResult;
  } else if (mode === "passkey") {
    const { result } = confirmationResult as PasskeyConfirmationResult;
    const cookiesValidationResult = await ctx.passkeyService.validateLoginChallengeCookie(cookies);
    if (!cookiesValidationResult.ok) {
      return { error: cookiesValidationResult.error, code: TwoFactorErrorCode.INVALID };
    }
    const verificationResult = await ctx.passkeyService.verifyPasskeyResponse(result, opts.userPk, cookiesValidationResult.decodedPasskeysCookies );

    if (verificationResult.ok && verificationResult.passkeyConfirmed) {
      if (ctx.options.stepUpMfaGracePeriodSeconds) {
        ctx.cookieService.issueMfaGrace({ headers: opts.extra?.headers, response }, cookies);
      }
      return  { ok: true }
    }
    return { error: "Invalid passkey", code: TwoFactorErrorCode.INVALID }
  }
  return { error: "Unsupported confirmation mode", code: TwoFactorErrorCode.UNSUPPORTED_MODE };
}
