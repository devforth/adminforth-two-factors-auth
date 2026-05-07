import { Filters } from "adminforth";
import {
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';

export function getPasskeysRpID(plugin: any): string {
  return plugin.options.passkeys?.settings?.rp?.id || (new URL(plugin.options.passkeys.settings.expectedOrigin)).hostname;
}

export async function validateCookiesForPasskeyLogin(plugin: any, cookies: any): Promise<{ok: boolean, decodedPasskeysCookies?: any, error?: string}> {
  const passkeysCookies = plugin.adminforth.auth.getCustomCookie({cookies: cookies, name: `passkeyLoginTemporaryJWT`});
  if (!passkeysCookies) {
    return { ok: false, error: 'Passkey token is required' };
  }

  const decodedPasskeysCookies = await plugin.adminforth.auth.verify(passkeysCookies, 'tempLoginPasskeyChallenge', false);
  if (!decodedPasskeysCookies?.challenge) {
    return { ok: false, error: 'Invalid passkey' };
  }

  return { ok: true, decodedPasskeysCookies };
}

export async function verifyPasskeyResponse(plugin: any, body: any, user_id: string, cookies: any) {
  const settingsOrigin = plugin.options.passkeys?.settings.expectedOrigin;
  const expectedOrigin = body.origin;
  const expectedChallenge = cookies.challenge;
  const expectedRPID = getPasskeysRpID(plugin);
  try {
    if (!body?.response) {
      throw new Error('Passkey response is required.');
    }
    const response = JSON.parse(body.response);
    if (settingsOrigin !== expectedOrigin) {
      throw new Error(`Origin mismatch. Allowed in settings: ${settingsOrigin}, received from client: ${expectedOrigin}`);
    }
    const cred = await plugin.adminforth.resource(plugin.options.passkeys.credentialResourceID).get([Filters.EQ(plugin.options.passkeys.credentialIdFieldName, response.id)]);
    if (!cred) {
      throw new Error('Credential not found.');
    }
    const credMeta = JSON.parse(cred[plugin.options.passkeys.credentialMetaFieldName]);
    if (!credMeta || !credMeta.public_key) {
      throw new Error('Credential public key not found.');
    }
    const userResourceId = plugin.adminforth.config.auth.usersResourceId;
    const usersResource = plugin.adminforth.config.resources.find(r => r.resourceId === userResourceId);
    const usersPrimaryKeyColumn = usersResource.columns.find((col) => col.primaryKey);
    const usersPrimaryKeyFieldName = usersPrimaryKeyColumn.name;
    const user = await plugin.adminforth.resource(userResourceId).get([Filters.EQ(usersPrimaryKeyFieldName, cred[plugin.options.passkeys.credentialUserIdFieldName])]);
    if (!user || !user_id || user[usersPrimaryKeyFieldName] !== user_id) {
      throw new Error('User not found.');
    }
    const isChallangeValid = await plugin.lockUnusedChellenge(expectedChallenge);
    if (!isChallangeValid) {
      return { ok: false, error: 'Invalid passkey' };
    }
    try {
      const transports = typeof credMeta.transports === 'string'
        ? JSON.parse(credMeta.transports || '[]')
        : credMeta.transports;
      const { verified, authenticationInfo } = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: settingsOrigin,
        expectedRPID,
        credential: {
          id: cred[plugin.options.passkeys.credentialIdFieldName],
          publicKey: isoBase64URL.toBuffer(credMeta.public_key),
          counter: credMeta.sign_count ?? credMeta.counter ?? 0,
          transports,
        },
        requireUserVerification: plugin.options.passkeys?.settings.authenticatorSelection?.userVerification === 'discouraged' ? false : true,
      });

      if (!verified) {
        return { ok: false, error: 'User verification failed.' };
      }
      await plugin.useChellenge(expectedChallenge, plugin.options.passkeys?.challengeValidityPeriod || '2m');
      credMeta.sign_count = authenticationInfo.newCounter;
      delete credMeta.counter;
      credMeta.last_used_at = new Date().toISOString();
      const credResource = plugin.adminforth.config.resources.find(r => r.resourceId === plugin.options.passkeys.credentialResourceID);
      const credResourcePKColumn = credResource?.columns.find(c => c.primaryKey);
      if (!credResource || !credResourcePKColumn) {
        throw new Error('Credential resource or its primary key is not configured correctly');
      }
      const credResourcePKName = credResourcePKColumn.name;
      await plugin.adminforth
        .resource(plugin.options.passkeys.credentialResourceID)
        .update(cred[credResourcePKName], { [plugin.options.passkeys.credentialMetaFieldName]: JSON.stringify(credMeta) });
      return { ok: true, passkeyConfirmed: true };
    } finally {
      plugin.unlockChellenge(expectedChallenge);
    }
  } catch (e) {
    return { ok: false, error: 'Error authenticating passkey: ' + e };
  }
}
