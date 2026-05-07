import crypto from 'crypto';

export function generateHashForStepUpMfaGraceCookie(plugin: any, headers: any, cookies: any): string {
  const ip = plugin.adminforth.auth.getClientIp(headers);
  const userAgent = headers['user-agent'] || '';
  const acceptLanguage = headers['accept-language'] || '';
  const session_cookie = plugin.adminforth.auth.getCustomCookie({cookies: cookies, name: "jwt"});
  if (!ip || !userAgent || !acceptLanguage || !session_cookie) {
    console.error("❗️❗️❗️ Cannot set step-up MFA grace cookie: missing required request headers to identify client ❗️❗️❗️");
    return null;
  } else {
    const hmac = crypto.createHmac('sha256', process.env.ADMINFORTH_SECRET)
      .update(`${acceptLanguage}_${userAgent}_${ip}_${session_cookie}`)
      .digest('hex');
    return hmac;
  }
}

export function issueTempSkip2FAGraceJWT(plugin: any, opts: any, cookies: any, response: any): void {
  if (response) {
    if (opts.extra.headers) {
      const hash = generateHashForStepUpMfaGraceCookie(plugin, opts.extra.headers, cookies);
      if (!hash) {
        return;
      }
      const jwt = plugin.adminforth.auth.issueJWT({ hash: hash }, 'MfaGrace', `${plugin.options.stepUpMfaGracePeriodSeconds}s`);
      //TODO: fix ts-ignore after releasing new version of adminforth with updated types
      //@ts-ignore
      plugin.adminforth.auth.setCustomCookie({response: response, payload: {name: "TempSkip2FA_Modal_JWT", sessionBased: true, value: jwt, httpOnly: true}});
    }
  } else {
    console.error("❗️❗️❗️ Cannot set step-up MFA grace cookie: response object is missing. You probably called verify() method without response parameter ❗️❗️❗️");
  }
}

export async function isTempSkip2FAGraceValid(plugin: any, headers: any, cookies: any, checkIfJWTAboutToExpire: boolean = false): Promise<boolean> {
  const hash = generateHashForStepUpMfaGraceCookie(plugin, headers, cookies);
  if (!hash) {
    return false;
  }
  const jwt = plugin.adminforth.auth.getCustomCookie({cookies: cookies, name: "TempSkip2FA_Modal_JWT"});
  const jwtVerificationResult = await plugin.adminforth.auth.verify(jwt, 'MfaGrace', false)
  if (!jwtVerificationResult) {
    return false;
  }
  const jwtHash = jwtVerificationResult['hash'];
  if (checkIfJWTAboutToExpire && (jwtVerificationResult["exp"] - ( Date.now() / 1000)) < 30 ) {
    console.error("❗️❗️❗️ Cannot validate step-up MFA grace cookie: token is expired or about to expire ❗️❗️❗️");
    return false;
  }
  if (hash === jwtHash) {
    return true;
  }
  return false;
}
