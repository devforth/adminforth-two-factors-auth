import {  AdminForthPlugin, Filters } from "adminforth";
import type { AdminForthResource, AdminUser, IAdminForth, IHttpServer, IAdminForthAuth, BeforeLoginConfirmationFunction, IAdminForthHttpResponse } from "adminforth";
import twofactor from 'node-2fa';
import  { PluginOptions } from "./types.js"
import crypto from 'crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoUint8Array, isoBase64URL } from '@simplewebauthn/server/helpers';

const challenges = new Map();
export default class TwoFactorsAuthPlugin extends AdminForthPlugin {
  options: PluginOptions;
  adminforth: IAdminForth;
  authResource: AdminForthResource;
  connectors: any;
  adminForthAuth: IAdminForthAuth;

  constructor(options: PluginOptions) {
    super(options, import.meta.url);
    this.options = options;
  }

  instanceUniqueRepresentation(pluginOptions: any) : string {
    return `single`;
  }

  public async verify(
    code: string,
    opts?: { adminUser?: AdminUser; userPk?: string }
  ): Promise<{ ok: true } | { error: string }> {
    if (!code) return { error: "Code is required" };

    const authRes = this.adminforth.config.resources
      .find(r => r.resourceId === this.adminforth.config.auth.usersResourceId);

    if (!authRes) return { error: "Auth resource not found" };

    const connector = this.adminforth.connectors[authRes.dataSource];
    const pkName = authRes.columns.find(c => c.primaryKey)?.name;
    if (!pkName) return { error: "Primary key not found on auth resource" };

    const pk = opts?.userPk ?? opts?.adminUser?.dbUser?.[pkName];
    if (!pk) return { error: "User PK is required" };

    const user = await connector.getRecordByPrimaryKey(authRes, pk);
    if (!user) return { error: "User not found" };

    const secret = user[this.options.twoFaSecretFieldName];
    if (!secret) return { error: "2FA is not set up for this user" };

    const verified = twofactor.verifyToken(secret, code, this.options.timeStepWindow);
    return verified ? { ok: true } : { error: "Wrong or expired OTP code" };
  }

  public parsePeriod(period?: string): number {
    if (!period) return 0;

    const match = /^(\d+)([dhms])$/.exec(period.trim());
    if (!match) throw new Error(`Invalid suggestionPeriod format: ${period}`);

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 'd': return value * 24 * 60 * 60 * 1000; 
      case 'h': return value * 60 * 60 * 1000; 
      case 'm': return value * 60 * 1000;
      case 's': return value * 1000;
      default: return value;
    }
  }

  public bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    return btoa(str)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  modifyResourceConfig(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
    super.modifyResourceConfig(adminforth, resourceConfig);
    this.adminforth = adminforth;
    this.adminForthAuth = adminforth.auth;
    const isPasskeysEnabled = this.options.passkeys ? true : false;
    const suggestionPeriod = this.parsePeriod(this.options.passkeys?.suggestionPeriod || "5d");

    const customPages = this.adminforth.config.customization.customPages
    customPages.push({
      path:'/confirm2fa',
      component: { file: this.componentPath('TwoFactorsConfirmation.vue'), meta: { customLayout: true, suggestionPeriod: suggestionPeriod } }
    })
    customPages.push({
      path:'/setup2fa',
      component: { file: this.componentPath('TwoFactorsSetup.vue'), meta: { title: 'Setup 2FA', customLayout: true, suggestionPeriod: suggestionPeriod } }
    })
    const everyPageBottomInjections = this.adminforth.config.customization.globalInjections.everyPageBottom || []
    everyPageBottomInjections.push({ file: this.componentPath('TwoFAModal.vue'), meta: {} })
    this.activate( resourceConfig, adminforth )

    if ( this.options.passkeys ) {
      if( !this.adminforth.config.auth.userMenuSettingsPages ){
        this.adminforth.config.auth.userMenuSettingsPages = [];
      }
      this.adminforth.config.auth.userMenuSettingsPages.push({
        icon: 'flowbite:lock-solid',
        pageLabel: 'Passkeys',
        slug: 'passkeys',
        component: this.componentPath('TwoFactorsPasskeysSettings.vue'),
      });
    }
  }

  validateConfigAfterDiscover(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
    if (this.options.passkeys) {
      if (!this.options.passkeys.settings) {
        throw new Error('Passkeys settings are required when passkeys option is enabled');
      }
      if (!this.options.passkeys.settings.rp) {
        throw new Error('Passkeys settings.rp is required');
      }
      if (!this.options.passkeys.settings.user.nameField) {
        throw new Error('Passkeys settings.user.nameField is required');
      }
    }
  }

  activate ( resourceConfig: AdminForthResource, adminforth: IAdminForth ){
    if (!this.options.twoFaSecretFieldName){
      throw new Error('twoFaSecretFieldName is required')
    }
    if (typeof this.options.twoFaSecretFieldName !=='string'){
      throw new Error('twoFaSecretFieldName must be a string')
    }
    if (
      this.options.timeStepWindow === undefined
      || typeof this.options.timeStepWindow !== 'number'
      || this.options.timeStepWindow < 0
    )
      this.options.timeStepWindow = 1;

    this.authResource = resourceConfig
    if(!this.authResource.columns.some((col)=>col.name === this.options.twoFaSecretFieldName)){
      throw new Error(`Column ${this.options.twoFaSecretFieldName} not found in ${this.authResource.label}`)
    }

    const beforeLoginConfirmation = this.adminforth.config.auth.beforeLoginConfirmation;
    const beforeLoginConfirmationArray = Array.isArray(beforeLoginConfirmation) ? beforeLoginConfirmation : [beforeLoginConfirmation];
    beforeLoginConfirmationArray.push(
      async({ adminUser, response, extra }: { adminUser: AdminUser, response: IAdminForthHttpResponse, extra?: any} )=> {
        const secret = adminUser.dbUser[this.options.twoFaSecretFieldName]
        const userName = adminUser.dbUser[adminforth.config.auth.usernameField]
        const brandName = adminforth.config.customization.brandName;
        const brandNameSlug = adminforth.config.customization.brandNameSlug;
        const issuerName = (this.options.customBrendPrefix && this.options.customBrendPrefix.trim())
        ? this.options.customBrendPrefix.trim()
        : brandName;
        const authResource = adminforth.config.resources.find((res)=>res.resourceId === adminforth.config.auth.usersResourceId )
        const authPk = authResource.columns.find((col)=>col.primaryKey).name
        const userPk = adminUser.dbUser[authPk]
        const rememberMe = extra?.body?.rememberMe || false;
        const rememberMeDays = rememberMe ? adminforth.config.auth.rememberMeDays || 30 : 1;
        let newSecret = null;

        const userNeeds2FA = this.options.usersFilterToApply ? this.options.usersFilterToApply(adminUser) : true;
        if (!userNeeds2FA){
          return { body:{loginAllowed: true}, ok: true}
        }

        const userCanSkipSetup = this.options.usersFilterToAllowSkipSetup ? this.options.usersFilterToAllowSkipSetup(adminUser) : false;

        if (!secret){
          const tempSecret = twofactor.generateSecret({name: issuerName,account: userName})
          newSecret = tempSecret.secret
        } else {
          const value = this.adminforth.auth.issueJWT({userName, issuer:issuerName, pk:userPk, userCanSkipSetup, rememberMeDays }, 'tempTotp', '2h');
          response.setHeader('Set-Cookie', `adminforth_${brandNameSlug}_totpTemporaryJWT=${value}; Path=${this.adminforth.config.baseUrl || '/'}; HttpOnly; SameSite=Strict; max-age=3600; `);

          return {
            body:{
              loginAllowed: false,
              redirectTo: '/confirm2fa',
            },
            ok: true
          }
        }
        const totpTemporaryJWT = this.adminforth.auth.issueJWT({userName, newSecret, issuer:issuerName, pk:userPk, userCanSkipSetup, rememberMeDays }, 'tempTotp', '2h');
        response.setHeader('Set-Cookie', `adminforth_${brandNameSlug}_totpTemporaryJWT=${totpTemporaryJWT}; Path=${this.adminforth.config.baseUrl || '/'}; HttpOnly; SameSite=Strict; Expires=${new Date(Date.now() + '1h').toUTCString() } `);

        return {
          body:{
            loginAllowed: false,
            redirectTo: secret ? '/confirm2fa' : '/setup2fa',
          },
          ok: true
        }
      })
  }

  setupEndpoints(server: IHttpServer): void {
    server.endpoint({
      method: 'POST',
      path: `/plugin/twofa/initSetup`,
      noAuth: true,
      handler: async (server) => {
        const toReturn = {totpJWT:null,status:'ok',}
        const brandNameSlug = this.adminforth.config.customization.brandNameSlug;

        const totpTemporaryJWT = server.cookies.find((cookie)=>cookie.key === `adminforth_${brandNameSlug}_totpTemporaryJWT`)?.value;
        if (totpTemporaryJWT){
          toReturn.totpJWT = totpTemporaryJWT
        }
        return toReturn
      }
    })
    server.endpoint({
      method: 'POST',
      path: `/plugin/twofa/confirmSetup`,
      noAuth: true,
      handler: async ({ body, adminUser, response, cookies  }) => {
        const brandNameSlug = this.adminforth.config.customization.brandNameSlug;
        const totpTemporaryJWT = cookies.find((cookie)=>cookie.key === `adminforth_${brandNameSlug}_totpTemporaryJWT`)?.value;
        const decoded = await this.adminforth.auth.verify(totpTemporaryJWT, 'tempTotp');
        if (!decoded)
          return {status:'error',message:'Invalid token'}

        if (decoded.newSecret) {
          const verified = body.skip && decoded.userCanSkipSetup ? true : twofactor.verifyToken(decoded.newSecret, body.code, this.options.timeStepWindow);
          if (verified) {
            this.connectors = this.adminforth.connectors
            if (!body.skip) {
              const connector = this.connectors[this.authResource.dataSource];
              await connector.updateRecord({resource:this.authResource, recordId:decoded.pk, newValues:{[this.options.twoFaSecretFieldName]: decoded.newSecret}})
            }
            this.adminforth.auth.removeCustomCookie({response, name:'totpTemporaryJWT'})
            this.adminforth.auth.setAuthCookie({expireInDays: decoded.rememberMeDays, response, username:decoded.userName, pk:decoded.pk})
            return { status: 'ok', allowedLogin: true }
          } else {
            return {error: 'Wrong or expired OTP code'}
          }
        } else {
         // user already has secret, get it
          this.connectors = this.adminforth.connectors
          const connector = this.connectors[this.authResource.dataSource];
          const user = await connector.getRecordByPrimaryKey(this.authResource, decoded.pk)
          const verified = twofactor.verifyToken(user[this.options.twoFaSecretFieldName], body.code, this.options.timeStepWindow);
          if (verified) {
            this.adminforth.auth.removeCustomCookie({response, name:'totpTemporaryJWT'})
            this.adminforth.auth.setAuthCookie({expireInDays: decoded.rememberMeDays, response, username:decoded.userName, pk:decoded.pk})
            return { status: 'ok', allowedLogin: true }
          } else {
            return {error: 'Wrong or expired OTP code'}
          }
        }
      }
    })
    server.endpoint({
      method: "GET",
      path: "/plugin/twofa/skip-allow",
      noAuth: true,
      handler: async ({ cookies }) => {
        const brandNameSlug = this.adminforth.config.customization.brandNameSlug;
        const totpTemporaryJWT = cookies.find(
          (cookie) => cookie.key === `adminforth_${brandNameSlug}_totpTemporaryJWT`
        )?.value;
        const decoded = await this.adminforth.auth.verify(
          totpTemporaryJWT,
          "tempTotp",
        );
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
    });
    server.endpoint({
      method: 'POST',
      path: `/plugin/twofa/verify`,
      noAuth: false,
      handler: async ({ adminUser, body }) => {
        if (!body?.code) return { error: 'Code is required' };
    
        const authRes = this.adminforth.config.resources
          .find(r => r.resourceId === this.adminforth.config.auth.usersResourceId);
        const connector = this.adminforth.connectors[authRes.dataSource];
        const pkName = authRes.columns.find(c => c.primaryKey).name;
        const user = await connector.getRecordByPrimaryKey(authRes, adminUser.dbUser[pkName]);
    
        const secret = user[this.options.twoFaSecretFieldName];
        if (!secret) return { error: '2FA is not set up for this user' };
    
        const verified = twofactor.verifyToken(secret, body.code, this.options.timeStepWindow);
        return verified ? { ok: true } : { error: 'Wrong or expired OTP code' };
      }
    });
    server.endpoint({
      method: 'POST',
      path: `/plugin/passkeys/registerPasskeyRequest`,
      noAuth: false,
      handler: async ({ adminUser, response }) => {
        console.log("Passkey registration request for user:", adminUser);
        const rp = {
          name: this.options.passkeys?.settings.rp.name || this.adminforth.config.customization.brandName,
          id: this.options.passkeys?.settings.rp.id,
        };
        const userResourceId = this.adminforth.config.auth.usersResourceId;
        const usersResource = this.adminforth.config.resources.find(r => r.resourceId === userResourceId);
        const usersPrimaryKeyColumn = usersResource.columns.find((col) => col.primaryKey);
        const usersPrimaryKeyFieldName = usersPrimaryKeyColumn.name;
        const userInfo = await this.adminforth.resource(userResourceId).get( [Filters.EQ(usersPrimaryKeyFieldName, adminUser.pk)] );
        const user = {
          id: adminUser.pk,
          name: userInfo[this.options.passkeys?.settings.user.nameField],
          displayName: userInfo[this.options.passkeys?.settings.user.displayNameField],
        };
        const excludeCredentials = [];
        const temp = await this.adminforth.resource('passkeys').list( [Filters.EQ("user_id", adminUser.pk)] );
        for (const rec of temp) {
          if (rec.credential_id && rec.credential_id.length > 0) {
            excludeCredentials.push({
              id: rec.credential_id,
              type: "public-key",
              transports: JSON.parse(rec.transports || '[]')
            });
          }
        }
        const options = await generateRegistrationOptions({
          rpName: rp.name,
          rpID: rp.id,
          userID: isoUint8Array.fromUTF8String(user.id),
          userName: user.name,
          userDisplayName: user.displayName || '',
          attestationType: 'none',
          excludeCredentials,
          authenticatorSelection: {
            authenticatorAttachment: this.options.passkeys?.settings.authenticatorSelection.authenticatorAttachment || 'platform',
            requireResidentKey: this.options.passkeys?.settings.authenticatorSelection.requireResidentKey || true,
            userVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification || "required"
          },
        });
        const challengeId = crypto.randomUUID();
        challenges.set(challengeId, options.challenge);
        setTimeout(() => challenges.delete(challengeId), 600_000);
        return { ok: true, data: options, challengeId: challengeId};
      }
    });
    server.endpoint({
      method: 'POST',
      path: `/plugin/passkeys/finishRegisteringPasskey`,
      noAuth: false,
      handler: async ({body, adminUser }) => {
        const challengeId = body.challengeId;
        const expectedChallenge = challenges.get(challengeId);
        const expectedOrigin = body.origin;
        const expectedRPID = this.options.passkeys?.settings.rp.id;
        const response = JSON.parse(body.credential);
         try {
          // Verify the credential
          const { verified, registrationInfo } = await verifyRegistrationResponse({
            response,
            expectedChallenge,
            expectedOrigin,
            expectedRPID,
            requireUserVerification: false,
          });

          if (!verified) {
            throw new Error('Verification failed.');
          }
          const {
            aaguid,
            credential,
            credentialBackedUp
          } = registrationInfo;
          
          const credentialPublicKey = credential.publicKey;
          const credentialID = credential.id;

          const base64CredentialID = credentialID;
          const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);

          await this.adminforth.resource('passkeys').create({
            id                      : crypto.randomUUID(),
            user_id                 : adminUser.pk,
            credential_id           : base64CredentialID,
            public_key              : base64PublicKey,
            public_key_algorithm    : response.response.publicKeyAlgorithm,
            sign_count              : 0,
            transports              : JSON.stringify(response.response.transports),
            created_at              : new Date().toISOString(),
            last_used_at            : new Date().toISOString(),
            aaguid                  : aaguid,
            name                    : `Passkey ${adminUser.username}`,
          });
        } catch (error) {
          console.error(error);
          return { error: 'Error registering passkey: ' + error.message };
        }
        return { ok: true };
      }
    });
  }
}