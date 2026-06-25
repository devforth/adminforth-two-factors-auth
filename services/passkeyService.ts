import { convertPeriodToSeconds } from "adminforth";
import type { AdminUser, IAdminForth, IAdminForthHttpResponse, PeriodString } from "adminforth";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoUint8Array, isoBase64URL } from '@simplewebauthn/server/helpers';
import aaguids from '../custom/aaguid.json';
import type { PluginOptions } from "../types.js";
import { PasskeyRepository } from "../repositories/passkeyRepository.js";
import { UserRepository } from "../repositories/userRepository.js";
import { CookieService } from "./cookieService.js";
import { errorMessage, errorResult, prefixedErrorResult } from "../utils/errors.js";
import type { CookieList } from "../utils/types.js";

type PasskeyAuthenticationPayload = {
  response: string;
  origin: string;
};

type PasskeyRegistrationPayload = {
  credential: string;
  origin: string;
};

type PluginAuthenticatorAttachment = NonNullable<NonNullable<
  NonNullable<PluginOptions["passkeys"]>["settings"]["authenticatorSelection"]
>["authenticatorAttachment"]>;
type WebAuthnAuthenticatorAttachment = Exclude<PluginAuthenticatorAttachment, "both">;

export class PasskeyService {
  constructor(
    private readonly options: PluginOptions,
    private readonly adminforth: IAdminForth,
    private readonly userRepository = new UserRepository(adminforth, options),
    private readonly passkeyRepository = new PasskeyRepository(adminforth, options),
    private readonly cookieService = new CookieService(adminforth, options),
  ) {}

  private async markChallengeAsUsed(challenge: string, expiresIn?: PeriodString): Promise<void> {
    const expiresInSeconds = expiresIn ? convertPeriodToSeconds(expiresIn) : undefined;
    await this.options.passkeys.keyValueAdapter.set(challenge, 'stub_value', expiresInSeconds);
  }

  private async isChallengeUnused(challenge: string): Promise<boolean> {
    const res = await this.options.passkeys.keyValueAdapter.get(challenge);
    return !res;
  }

  public async validateLoginChallengeCookie(cookies: CookieList): Promise<{ok: boolean, decodedPasskeysCookies?: { challenge: string }, error?: string}> {
    const passkeysCookies = this.cookieService.getPasskeyLoginTemporary(cookies);
    if (!passkeysCookies) {
      return errorResult('Passkey token is required');
    }

    const decodedPasskeysCookies = await this.cookieService.verifyPasskeyLoginTemporary(cookies);
    if (!decodedPasskeysCookies?.challenge) {
      return errorResult('Invalid passkey');
    }

    const isChallangeValid = await this.isChallengeUnused(decodedPasskeysCookies.challenge);
    if (isChallangeValid) {
      await this.markChallengeAsUsed(decodedPasskeysCookies.challenge, this.options.passkeys?.challengeValidityPeriod || '2m');
    }

    if (!decodedPasskeysCookies || !isChallangeValid) {
      return errorResult('Invalid passkey');
    }
    return { ok: true, decodedPasskeysCookies };
  }

  public async verifyPasskeyResponse(body: PasskeyAuthenticationPayload, user_id: string, cookies: { challenge: string }) {
    const settingsOrigin = this.options.passkeys?.settings.expectedOrigin;
    const expectedOrigin = body.origin;
    const expectedChallenge = cookies.challenge;
    const expectedRPID = this.options.passkeys?.settings?.rp?.id || (new URL(settingsOrigin)).hostname;
    try {
      const response = JSON.parse(body.response);
      if (settingsOrigin !== expectedOrigin) {
        throw new Error(`Origin mismatch. Allowed in settings: ${settingsOrigin}, received from client: ${expectedOrigin}`);
      }
      const cred = await this.passkeyRepository.getByCredentialId(response.id);
      if (!cred) {
        throw new Error('Credential not found.');
      }
      const credMeta = cred[this.options.passkeys.credentialMetaFieldName];
      if (!credMeta || !credMeta.public_key) {
        throw new Error('Credential public key not found.');
      }
      const usersPrimaryKeyFieldName = this.userRepository.getUserPkField();
      const user = await this.userRepository.getAuthUser(cred[this.options.passkeys.credentialUserIdFieldName]);
      if (!user || !user_id || user[usersPrimaryKeyFieldName] !== user_id) {
        throw new Error('User not found.');
      }
      const counter = credMeta.sign_count ?? 0;
      const { verified, authenticationInfo } = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: settingsOrigin,
        expectedRPID,
        credential: {
          id: cred[this.options.passkeys.credentialIdFieldName],
          publicKey: isoBase64URL.toBuffer(credMeta.public_key),
          counter,
          transports: credMeta.transports,
        },
        requireUserVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification === 'discouraged' ? false : true,
      });

      if (!verified) {
        return errorResult('User verification failed.');
      }
      credMeta.sign_count = authenticationInfo.newCounter;
      credMeta.last_used_at = new Date().toISOString();
      await this.passkeyRepository.updateMeta(cred, credMeta);
      return { ok: true, passkeyConfirmed: true };
    } catch (e) {
      return prefixedErrorResult('Error authenticating passkey: ', e);
    }
  }

  public async createRegistrationOptions(mode: PluginAuthenticatorAttachment, adminUser: AdminUser, response: IAdminForthHttpResponse) {
    const settingsOrigin = this.options.passkeys?.settings.expectedOrigin;
    const authenticatorAttachment: WebAuthnAuthenticatorAttachment | undefined = mode === "both" ? undefined : mode;
    const rp = {
      name: this.options.passkeys?.settings.rp?.name || this.adminforth.config.customization.brandName,
      id: this.options.passkeys?.settings?.rp?.id || (new URL(settingsOrigin)).hostname,
    };
    const userInfo = await this.userRepository.getAuthUser(adminUser.pk);
    if (!userInfo) {
       return errorResult('User not found');
     }
    const user = {
      pk: adminUser.pk,
      name: userInfo[this.options.passkeys?.settings.user.nameField],
      displayName: userInfo[this.options.passkeys?.settings.user.displayNameField] ? userInfo[this.options.passkeys?.settings.user.displayNameField] : userInfo[this.options.passkeys?.settings.user.nameField],
    };
    const excludeCredentials = [];
    const temp = await this.passkeyRepository.listByUserId(adminUser.pk);
    for (const rec of temp) {
      const credentialId = rec[this.options.passkeys.credentialIdFieldName];
      if (credentialId) {
        const meta = rec[this.options.passkeys.credentialMetaFieldName];
        excludeCredentials.push({
          id: credentialId,
          type: "public-key",
          transports: meta.transports || []
        });
      }
    }
    const options = await generateRegistrationOptions({
      rpName: rp.name,
      rpID: rp.id,
      userID: isoUint8Array.fromUTF8String(user.pk),
      userName: user.name,
      userDisplayName: user.displayName,
      excludeCredentials,
      authenticatorSelection: {
        authenticatorAttachment,
        requireResidentKey: this.options.passkeys?.settings.authenticatorSelection.requireResidentKey ?? true,
        userVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification || "required"
      },
    });
    this.cookieService.setRegisterPasskeyTemporary(response, { challenge: options.challenge, user_id: adminUser.pk });
    return { ok: true, data: options };
  }

  public async finishRegistration(body: PasskeyRegistrationPayload, adminUser: AdminUser, cookies: CookieList) {
    const passkeysCookies = this.cookieService.getRegisterPasskeyTemporary(cookies);
    if (!passkeysCookies) {
      return { error: 'Passkey token is required' };
    }
    const decodedPasskeysCookies = await this.cookieService.verifyRegisterPasskeyTemporary(cookies);
    if (!decodedPasskeysCookies) {
      return { error: 'Invalid passkey token' };
    }
    if (decodedPasskeysCookies.user_id !== adminUser.pk) {
      return { error: 'Invalid user' };
    }
    const secret = this.userRepository.getSecret(adminUser.dbUser)
    if (!secret || secret.length === 0) {
      return { error: 'TOTP must be set up before registering a passkey' };
    }
    const settingsOrigin = this.options.passkeys?.settings.expectedOrigin;
    const expectedOrigin = body.origin;
    const expectedChallenge = decodedPasskeysCookies.challenge;
    const expectedRPID = this.options.passkeys?.settings?.rp?.id || (new URL(settingsOrigin)).hostname;
    try {
      const response = JSON.parse(body.credential);
      if (settingsOrigin !== expectedOrigin) {
        throw new Error('Invalid origin');
      }
      const { verified, registrationInfo } = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
        requireUserVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification === 'discouraged' ? false : true,
      });

      if (!verified) {
        throw new Error('Verification failed.');
      }
      const {
        aaguid,
        credential,
      } = registrationInfo;
      const provider_name = aaguids[aaguid]?.name || 'Unknown provider';
      const credentialPublicKey = credential.publicKey;
      const credentialID = credential.id;

      const base64CredentialID = credentialID;
      const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);

      await this.passkeyRepository.create({
          [this.options.passkeys.credentialIdFieldName]           : base64CredentialID,
          [this.options.passkeys.credentialUserIdFieldName]       : adminUser.pk,
          [this.options.passkeys.credentialMetaFieldName]         : {
            public_key              : base64PublicKey,
            public_key_algorithm    : response.response.publicKeyAlgorithm,
            sign_count              : 0,
            transports              : response.response.transports,
            created_at              : new Date().toISOString(),
            last_used_at            : new Date().toISOString(),
            aaguid                  : aaguid,
            name                    : provider_name,
          },
      }, adminUser);
    } catch (error) {
      console.error(error);
      return { error: 'Error registering passkey: ' + errorMessage(error) };
    }
    return { ok: true };
  }

  public async createLoginOptions(response: IAdminForthHttpResponse) {
    try {
      const options = await generateAuthenticationOptions({
        rpID: this.options.passkeys?.settings.rp?.id || (new URL(this.options.passkeys?.settings.expectedOrigin)).hostname,
        userVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification || "required"
      });
      this.cookieService.setPasskeyLoginTemporary(response, options.challenge);
      return { ok: true, data: options };
    } catch (e) {
      return { ok: false, error: errorMessage(e) };
    }
  }

  public async getPasskeys(adminUser: AdminUser) {
    let passkeys;
    try {
      passkeys = await this.passkeyRepository.listByUserId(adminUser.pk);
    } catch (error) {
      return prefixedErrorResult('Error fetching passkeys: ', error);
    }
    let dataToReturn = [];
    for (const pk of passkeys) {
      const parsedKey = pk[this.options.passkeys.credentialMetaFieldName];
      dataToReturn.push({
        name: parsedKey.name,
        light_icon: aaguids[parsedKey.aaguid]?.icon_light || null,
        dark_icon: aaguids[parsedKey.aaguid]?.icon_dark || null,
        created_at: parsedKey.created_at,
        last_used_at: parsedKey.last_used_at,
        id: pk[this.options.passkeys.credentialIdFieldName],
      });
    }
    return { ok: true, data: dataToReturn, authenticatorAttachment: this.options.passkeys?.settings.authenticatorSelection.authenticatorAttachment || 'both' };
  }

  public async deletePasskey(credentialID: string, adminUser: AdminUser) {
    if (!credentialID) {
      return errorResult('Passkey ID is required');
    }

    const passkeyRecord = await this.passkeyRepository.getByCredentialIdAndUserId(credentialID, adminUser.pk);
    if (!passkeyRecord) {
      return errorResult('Passkey not found');
    }
    try {
      await this.passkeyRepository.delete(passkeyRecord, adminUser);
    } catch (error) {
      return prefixedErrorResult('Error deleting passkey: ', error);
    }

    return { ok: true };
  }

  public async renamePasskey(credentialID: string, newName: string, adminUser: AdminUser) {
    if (!credentialID) {
      return errorResult('Passkey ID is required');
    }
    if (!newName) {
      return errorResult('New name is required');
    }
    const passkeyRecord = await this.passkeyRepository.getByCredentialIdAndUserId(credentialID, adminUser.pk);
    if (!passkeyRecord) {
      return errorResult('Passkey not found');
    }
    const metaField = this.options.passkeys.credentialMetaFieldName;
    const oldMeta = passkeyRecord[metaField];
    const newMeta = { ...oldMeta, name: newName };
    const newRecord = { ...passkeyRecord, [metaField]: newMeta };
    try {
      await this.passkeyRepository.update(passkeyRecord, newRecord, adminUser);
    } catch (error) {
      return prefixedErrorResult('Error renaming passkey: ', error);
    }
    return { ok: true };
  }

  public async checkIfUserHasPasskeys(cookies: CookieList) {
    if (!this.options.passkeys) {
      return { ok: false, hasPasskeys: false };
    }
    const decoded = await this.cookieService.verifyTotpTemporary(cookies);
    if (!decoded)
      return errorResult('Invalid token')
    if (decoded.newSecret) {
      return { ok: true, hasPasskeys: false };
    }
    const hasPasskeys = await this.passkeyRepository.hasByUserId(decoded.pk);
    if (hasPasskeys) {
      return { ok: true, hasPasskeys: true };
    } else {
      return { ok: true, hasPasskeys: false };
    }
  }

  public async hasPasskeysForUser(userId: string): Promise<boolean> {
    return this.passkeyRepository.hasByUserId(userId);
  }

  public async getLoginUserByPasskeyResponse(passkeyResponse: PasskeyAuthenticationPayload, cookies: CookieList) {
    const cookiesValidationResult = await this.validateLoginChallengeCookie(cookies);
    if (!cookiesValidationResult.ok) {
      return { error: cookiesValidationResult.error };
    }

    let parsedPasskeyResponse;
    try {
      parsedPasskeyResponse = JSON.parse(passkeyResponse.response);
    } catch (e) {
      return { error: 'Malformed passkey response' };
    }
    const credential_id = parsedPasskeyResponse.id;
    if (!credential_id) {
      return { error: 'Credential ID is required' };
    }

    const passkeyRecord = await this.passkeyRepository.getByCredentialId(credential_id);
    if (!passkeyRecord) {
      return { error: 'No such passkey found, most likely it was removed on this website but you still have it on your device' };
    }

    const userPk = passkeyRecord[this.options.passkeys.credentialUserIdFieldName];
    if (!userPk) {
      return { error: 'User ID not found in passkey record' };
    }

    const user = await this.userRepository.getAuthUser(userPk);
    if (!user) {
      return { error: 'User not found' };
    }

    const verificationResult = await this.verifyPasskeyResponse(passkeyResponse, userPk, cookiesValidationResult.decodedPasskeysCookies);
    if (!verificationResult.ok || !verificationResult.passkeyConfirmed) {
      return { error: 'Passkey verification failed' };
    }

    return { ok: true, user };
  }
}
