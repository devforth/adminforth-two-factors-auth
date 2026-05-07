import type { IAdminForthHttpResponse } from "adminforth";
import twofactor from 'node-2fa';
import { validateCookiesForPasskeyLogin, verifyPasskeyResponse } from "./passkeys.js";

export function finishTotpLogin(plugin: any, response: IAdminForthHttpResponse, decoded: any) {
  plugin.adminforth.auth.removeCustomCookie({response, name:'2FaTemporaryJWT'})
  plugin.adminforth.auth.setAuthCookie({expireInDuration: decoded.sessionDuration, response, username:decoded.userName, pk:decoded.pk})
  return { status: 'ok', allowedLogin: true }
}

export async function confirmNewTotpSetup(plugin: any, body: any, decoded: any, response: IAdminForthHttpResponse) {
  const verified = body.skip && decoded.userCanSkipSetup
    ? true
    : twofactor.verifyToken(decoded.newSecret, body.code, plugin.options.timeStepWindow);

  if (!verified) {
    return { error: 'Wrong or expired OTP code' };
  }

  if (!body.skip) {
    const connector = plugin.adminforth.connectors[plugin.authResource.dataSource];
    await connector.updateRecord({
      resource: plugin.authResource,
      recordId: decoded.pk,
      newValues: {
        [plugin.options.twoFaSecretFieldName]: decoded.newSecret,
      },
    });
  }

  return finishTotpLogin(plugin, response, decoded);
}

export async function confirmPasskeyLogin(plugin: any, passkeyOptions: any, userPk: string, cookies: any): Promise<boolean> {
  const cookiesValidationResult = await validateCookiesForPasskeyLogin(plugin, cookies);
  if (!cookiesValidationResult.ok) {
    return false;
  }

  const res = await verifyPasskeyResponse(plugin, passkeyOptions, userPk, cookiesValidationResult.decodedPasskeysCookies);
  return res.ok && res.passkeyConfirmed;
}

export async function confirmTotpLogin(plugin: any, userPk: string, code: string): Promise<boolean> {
  const connector = plugin.adminforth.connectors[plugin.authResource.dataSource];
  const user = await connector.getRecordByPrimaryKey(plugin.authResource, userPk)
  return Boolean(twofactor.verifyToken(user[plugin.options.twoFaSecretFieldName], code, plugin.options.timeStepWindow));
}

export async function confirmExistingSecondFactor(plugin: any, body: any, decoded: any, response: IAdminForthHttpResponse, cookies: any) {
  const verified = body.usePasskey && plugin.options.passkeys
    ? await confirmPasskeyLogin(plugin, body.passkeyOptions, decoded.pk, cookies)
    : await confirmTotpLogin(plugin, decoded.pk, body.code);

  if (!verified) {
    return { error: 'Verification failed' };
  }

  return finishTotpLogin(plugin, response, decoded);
}
