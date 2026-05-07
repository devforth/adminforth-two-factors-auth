import type { IAdminForthHttpResponse } from "adminforth";
import twofactor from 'node-2fa';
import { validateCookiesForPasskeyLogin, verifyPasskeyResponse } from "./passkeys.js";

function finishTotpLogin(plugin: any, response: IAdminForthHttpResponse, decoded: any) {
  plugin.adminforth.auth.removeCustomCookie({response, name:'2FaTemporaryJWT'})
  plugin.adminforth.auth.setAuthCookie({expireInDuration: decoded.sessionDuration, response, username:decoded.userName, pk:decoded.pk})
  return { status: 'ok', allowedLogin: true }
}

export async function confirmLogin(plugin: any, body: any, response: IAdminForthHttpResponse, cookies: any) {
  const brandNameSlug = plugin.adminforth.config.customization.brandNameSlug;
  const totpTemporaryJWT = plugin.adminforth.auth.getCustomCookie({cookies: cookies, name: "2FaTemporaryJWT"});
  if (!totpTemporaryJWT) {
    return { error: 'Login session expired. Please log in again.' }
  }
  const decoded = await plugin.adminforth.auth.verify(totpTemporaryJWT, 'temp2FA');
  if (!decoded) {
    return { error: 'Login session expired. Please log in again.' }
  }

  if (decoded.newSecret) {
    // set up standard TOTP request - ensured by presence of newSecret in temp2FA token
    const verified = body.skip && decoded.userCanSkipSetup ? true : twofactor.verifyToken(decoded.newSecret, body.code, plugin.options.timeStepWindow);
    if (verified) {
      plugin.connectors = plugin.adminforth.connectors
      if (!body.skip) {
        const connector = plugin.connectors[plugin.authResource.dataSource];
        await connector.updateRecord({resource:plugin.authResource, recordId:decoded.pk, newValues:{[plugin.options.twoFaSecretFieldName]: decoded.newSecret}})
      }
      return finishTotpLogin(plugin, response, decoded);
    } else {
      return {error: 'Wrong or expired OTP code'}
    }
  } else {
    // login with confirming existing TOTP or Passkey
    let verified = null;
    if (body.usePasskey && plugin.options.passkeys) {
      // passkeys are enabled and user wants to use them
      const cookiesValidationResult = await validateCookiesForPasskeyLogin(plugin, cookies);
      if (!cookiesValidationResult.ok) {
        return { error: cookiesValidationResult.error };
      }
      const res = await verifyPasskeyResponse(plugin, body.passkeyOptions, decoded.pk, cookiesValidationResult.decodedPasskeysCookies);
      if (res.ok && res.passkeyConfirmed) {
        verified = true;
      }
    } else {
      // user already has TOTP secret, get it
      plugin.connectors = plugin.adminforth.connectors
      const connector = plugin.connectors[plugin.authResource.dataSource];
      const user = await connector.getRecordByPrimaryKey(plugin.authResource, decoded.pk)
      verified = twofactor.verifyToken(user[plugin.options.twoFaSecretFieldName], body.code, plugin.options.timeStepWindow);
    }
    if (verified) {
      return finishTotpLogin(plugin, response, decoded);
    } else {
      return {error: 'Verification failed'}
    }
  }
}
