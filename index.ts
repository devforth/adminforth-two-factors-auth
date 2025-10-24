import {  AdminForthPlugin, Filters, suggestIfTypo } from "adminforth";
import type { AdminForthResource, AdminUser, IAdminForth, IHttpServer, IAdminForthAuth, BeforeLoginConfirmationFunction, IAdminForthHttpResponse } from "adminforth";
import twofactor from 'node-2fa';
import  { PluginOptions } from "./types.js"
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoUint8Array, isoBase64URL } from '@simplewebauthn/server/helpers';
import aaguids from './custom/aaguid.json';

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

  public async checkIfSkipSetupAllowSkipVerify(adminUser: AdminUser): Promise<{ skipAllowed: boolean }> {
    if (this.options.usersFilterToAllowSkipSetup) {
      const res = await this.options.usersFilterToAllowSkipSetup(adminUser); // recieve result of usersFilterToAllowSkipSetup
      if (res === false) { // if false, user is not allowed to skip anyway, so doesn't matter if they have 2FA set up or not
        return { skipAllowed: true };
      }
      
      //recieve user's record
      const usersResource = this.adminforth.config.resources.find(r => r.resourceId === this.adminforth.config.auth.usersResourceId);
      const usersPrimaryKeyColumn = usersResource.columns.find((col) => col.primaryKey);
      const userPkFieldName = usersPrimaryKeyColumn.name;
      const userRecord = await this.adminforth.resource(this.adminforth.config.auth.usersResourceId).get([Filters.EQ(userPkFieldName, adminUser.pk)])

      //check if user has 2FA set up
      const users2FASecret = userRecord[this.options.twoFaSecretFieldName];
      //check if user has any passkeys registered
      const passkeys = await this.adminforth.resource(this.options.passkeys.credentialResourceID).list( [Filters.EQ(this.options.passkeys.credentialUserIdFieldName, adminUser.dbUser[userPkFieldName])] );

      // If user has either 2FA secret or any passkeys, they cannot skip
      if (users2FASecret || (passkeys && passkeys.length > 0)) {
        return { skipAllowed: false };
      }
      return { skipAllowed: res };
    }
    return { skipAllowed: false };
  }

  public async verify(
    confirmationResult: Record<string, any>,
    opts?: { adminUser?: AdminUser; userPk?: string; cookies?: any }
  ): Promise<{ ok: true } | { error: string }> {
    if (!confirmationResult) return { error: "Confirmation result is required" };
    if (this.options.usersFilterToApply) {
      const res = this.options.usersFilterToApply(opts.adminUser);
      if ( res === false ) {
        return { ok: true };
      }
    }
    if (this.options.usersFilterToAllowSkipSetup) {
      const res = await this.checkIfSkipSetupAllowSkipVerify(opts.adminUser);
      if ( res.skipAllowed === true ) {
        return { ok: true };
      }
    }
    if (confirmationResult.mode === "totp") {
      const code = confirmationResult.result;
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
    } else if (confirmationResult.mode === "passkey") {
      const passkeysCookies = this.adminforth.auth.getCustomCookie({cookies: opts.cookies, name: `passkeyLoginTemporaryJWT`});
      if (!passkeysCookies) {
        return { error: 'Passkey token is required' };
      }

      const decodedPasskeysCookies = await this.adminforth.auth.verify(passkeysCookies, 'tempLoginPasskeyChallenge', false);
      if (!decodedPasskeysCookies) {
        return { error: 'Invalid passkey' };
      }
      const verificationResult = await this.verifyPasskeyResponse(confirmationResult.result, opts.userPk, decodedPasskeysCookies );

      if (verificationResult.ok && verificationResult.passkeyConfirmed) {
        return  { ok: true }
      }
      return { error: "Invalid passkey" }
    }
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

  public async verifyPasskeyResponse(body: any, user_id: string, cookies: any) {
    const settingsOrigin = this.options.passkeys?.settings.expectedOrigin;
    const expectedOrigin = body.origin;
    const expectedChallenge = cookies.challenge;
    const expectedRPID = this.options.passkeys?.settings?.rp?.id || (new URL(settingsOrigin)).hostname;
    const response = JSON.parse(body.response);
    try {
      if (settingsOrigin !== expectedOrigin) {
        throw new Error(`Origin mismatch. Allowed in settings: ${settingsOrigin}, received from client: ${expectedOrigin}`);
      }
      const cred = await this.adminforth.resource(this.options.passkeys.credentialResourceID).get([Filters.EQ(this.options.passkeys.credentialIdFieldName, response.id)]);
      if (!cred) {
        throw new Error('Credential not found.');
      }
      const credMeta = JSON.parse(cred[this.options.passkeys.credentialMetaFieldName]);
      if (!credMeta || !credMeta.public_key) {
        throw new Error('Credential public key not found.');
      }
      const userResourceId = this.adminforth.config.auth.usersResourceId;
      const usersResource = this.adminforth.config.resources.find(r => r.resourceId === userResourceId);
      const usersPrimaryKeyColumn = usersResource.columns.find((col) => col.primaryKey);
      const usersPrimaryKeyFieldName = usersPrimaryKeyColumn.name;
      const user = await this.adminforth.resource(userResourceId).get([Filters.EQ(usersPrimaryKeyFieldName, cred[this.options.passkeys.credentialUserIdFieldName])]);
      if (!user || !user_id || user[usersPrimaryKeyFieldName] !== user_id) {
        throw new Error('User not found.');
      }
      const { verified, authenticationInfo } = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: settingsOrigin,
        expectedRPID,
        credential: {
          id: cred[this.options.passkeys.credentialIdFieldName],
          publicKey: isoBase64URL.toBuffer(credMeta.public_key),
          counter: credMeta.counter,
          transports: credMeta.transports,
        },
        requireUserVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification === 'discouraged' ? false : true,
      });

      if (!verified) {
        return { ok: false, error: 'User verification failed.' };
      }
      credMeta.counter = authenticationInfo.newCounter;
      credMeta.last_used_at = new Date().toISOString();
      await this.adminforth.resource(this.options.passkeys.credentialResourceID).update(cred[this.options.passkeys.credentialIdFieldName], { [this.options.passkeys.credentialMetaFieldName]: JSON.stringify(credMeta) });
      return { ok: true, passkeyConfirmed: true };
    } catch (e) {
      return { ok: false, error: 'Error authenticating passkey: ' + e };
    }
  }

  modifyResourceConfig(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
    super.modifyResourceConfig(adminforth, resourceConfig);
    this.adminforth = adminforth;
    this.adminForthAuth = adminforth.auth;
    const suggestionPeriod = this.parsePeriod(this.options.passkeys?.suggestionPeriod || "5d");
    const isPasskeysEnabled = this.options.passkeys ? true : false;

    const customPages = this.adminforth.config.customization.customPages
    customPages.push({
      path:'/confirm2fa',
      component: { file: this.componentPath('TwoFactorsConfirmation.vue'), meta: { sidebarAndHeader: "none", suggestionPeriod: suggestionPeriod, isPasskeysEnabled: isPasskeysEnabled } }
    })
    customPages.push({
      path:'/setup2fa',
      component: { file: this.componentPath('TwoFactorsSetup.vue'), meta: { title: 'Setup 2FA', sidebarAndHeader: "none", suggestionPeriod: suggestionPeriod, isPasskeysEnabled: isPasskeysEnabled  } }
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

      if ( this.options.passkeys.allowLoginWithPasskeys !== false ) {
        this.options.passkeys.allowLoginWithPasskeys = true;
        if ( !this.adminforth.config.customization.loginPageInjections ) {
          this.adminforth.config.customization.loginPageInjections = { underLoginButton: [],  panelHeader: [], underInputs: [] };
        } 
      (this.adminforth.config.customization.loginPageInjections.underLoginButton as Array<any>).push({ file: this.componentPath('LoginWithPasskeyButton.vue'), meta: { afOrder: this.options.passkeys.continueWithButtonsOrder || 0 } });
      }
    }
  }

  validateConfigAfterDiscover(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
    if (this.options.passkeys) {

      const adminForthResources = [];
      for (const res of adminforth.config.resources) {
        adminForthResources.push(res.resourceId);
      }
      if (!this.options.passkeys.credentialResourceID) {
        throw new Error('Passkeys credentialResourceID is required');
      }
      if ( !(adminForthResources.includes(this.options.passkeys.credentialResourceID)) ) {
        throw new Error('Passkeys credentialResourceID is not valid');
      }
      if (!this.options.passkeys.credentialIdFieldName) {
        throw new Error('Passkeys credentialIdFieldName is required');
      }

      const credentialResource = adminforth.config.resources.find(r => r.resourceId === this.options.passkeys.credentialResourceID); 
      const credentialIDField = credentialResource.columns.find(c => c.name === this.options.passkeys.credentialIdFieldName);
      if ( !credentialIDField ) {
        const similar = suggestIfTypo(credentialResource.columns.map(c => c.name), this.options.passkeys.credentialIdFieldName);
        throw new Error(
          `Passkeys credentialIdFieldName '${this.options.passkeys.credentialIdFieldName}' not found in resource '${this.options.passkeys.credentialResourceID}'. ${
            similar ? `Did you mean '${similar}'?` : ''
          }`
        );
      }
      credentialIDField.backendOnly = true;

      if (!this.options.passkeys.credentialMetaFieldName) {
        throw new Error('Passkeys credentialMetaFieldName is required');
      }

      const metaResource = adminforth.config.resources.find(r => r.resourceId === this.options.passkeys.credentialMetaFieldName); 
      const metaField = credentialResource.columns.find(c => c.name === this.options.passkeys.credentialMetaFieldName);
      if ( !metaField ) {
        const similar = suggestIfTypo(metaResource.columns.map(c => c.name), this.options.passkeys.credentialMetaFieldName);
        throw new Error(
          `Passkeys credentialMetaFieldName '${this.options.passkeys.credentialMetaFieldName}' not found in resource '${this.options.passkeys.credentialMetaFieldName}'. ${
            similar ? `Did you mean '${similar}'?` : ''
          }`
        );
      }
      metaField.backendOnly = true;


      if (!this.options.passkeys.credentialUserIdFieldName) {
        throw new Error('Passkeys credentialUserIdFieldName is required');
      }
      if (!this.options.passkeys.settings) {
        throw new Error('Passkeys settings are required when passkeys option is enabled');
      }
      if (!this.options.passkeys.settings.expectedOrigin) {
        throw new Error('Passkeys settings.expectedOrigin is required');
      }
      const origin = new URL( this.options.passkeys.settings.expectedOrigin ).origin;
      if ( origin !== this.options.passkeys.settings.expectedOrigin ) {
        throw new Error('Passkeys settings.expectedOrigin is not valid');
      }
      if (this.options.passkeys.settings.authenticatorSelection) {
        if (this.options.passkeys.settings.authenticatorSelection.authenticatorAttachment) {
          if ( !['platform', 'cross-platform', 'both'].includes(this.options.passkeys.settings.authenticatorSelection.authenticatorAttachment) ) {
            throw new Error('Passkeys settings.authenticatorSelection.authenticatorAttachment is not valid');
          }
        }
        if (this.options.passkeys.settings.authenticatorSelection.userVerification) {
          if ( !['required', 'discouraged'].includes(this.options.passkeys.settings.authenticatorSelection.userVerification) ) {
            throw new Error('Passkeys settings.authenticatorSelection.userVerification is not valid');
          }
        }
      }

      if (!this.options.passkeys.settings.user) {
        throw new Error('Passkeys settings.user is required');
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
        if (extra?.body?.loginAllowedByPasskeyDirectSignIn === true) {
          return { body: { loginAllowed: true }, ok: true };
        }
        const secret = adminUser.dbUser[this.options.twoFaSecretFieldName]
        const userName = adminUser.dbUser[adminforth.config.auth.usernameField]
        const brandName = adminforth.config.customization.brandName;
        const brandNameSlug = adminforth.config.customization.brandNameSlug;
        const issuerName = (this.options.customBrandPrefix && this.options.customBrandPrefix.trim())
        ? this.options.customBrandPrefix.trim()
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
          newSecret = tempSecret.secret;

          const totpTemporaryJWT = this.adminforth.auth.issueJWT({userName, newSecret, issuer:issuerName, pk:userPk, userCanSkipSetup, rememberMeDays }, 'temp2FA', this.options.passkeys?.challengeValidityPeriod || '1m');
          this.adminforth.auth.setCustomCookie({response, payload: {name: "2FaTemporaryJWT", value: totpTemporaryJWT, expiry: undefined, expirySeconds: 10 * 60, httpOnly: true}});

          return {
            body:{
              loginAllowed: false,
              redirectTo: secret ? '/confirm2fa' : '/setup2fa',
            },
            ok: true
          }

        } else {
          const value = this.adminforth.auth.issueJWT({userName, issuer:issuerName, pk:userPk, userCanSkipSetup, rememberMeDays }, 'temp2FA', this.options.passkeys?.challengeValidityPeriod || '1m');
          this.adminforth.auth.setCustomCookie({response, payload: {name: "2FaTemporaryJWT", value: value, expiry: undefined, expirySeconds: 10 * 60, httpOnly: true}});

          return {
            body:{
              loginAllowed: false,
              redirectTo: '/confirm2fa',
            },
            ok: true
          }
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
        const totpTemporaryJWT = this.adminforth.auth.getCustomCookie({cookies: server.cookies, name: "2FaTemporaryJWT"});
        if (totpTemporaryJWT){
          toReturn.totpJWT = totpTemporaryJWT
        }
        return toReturn
      }
    })

    // this enpoints sets final login cookie if 2nd factor is confirmed
    server.endpoint({
      method: 'POST',
      path: `/plugin/twofa/confirmLogin`,
      noAuth: true,
      handler: async ({ body, adminUser, response, cookies  }) => {
        const brandNameSlug = this.adminforth.config.customization.brandNameSlug;
        const totpTemporaryJWT = this.adminforth.auth.getCustomCookie({cookies: cookies, name: "2FaTemporaryJWT"});
        if (!totpTemporaryJWT) {
          return { error: 'Login session expired. Please log in again.' }
        }
        const decoded = await this.adminforth.auth.verify(totpTemporaryJWT, 'temp2FA');
        if (!decoded) {
          return { error: 'Login session expired. Please log in again.' }
        }

        if (decoded.newSecret) {
          // set up standard TOTP request - ensured by presence of newSecret in temp2FA token
          const verified = body.skip && decoded.userCanSkipSetup ? true : twofactor.verifyToken(decoded.newSecret, body.code, this.options.timeStepWindow);
          if (verified) {
            this.connectors = this.adminforth.connectors
            if (!body.skip) {
              const connector = this.connectors[this.authResource.dataSource];
              await connector.updateRecord({resource:this.authResource, recordId:decoded.pk, newValues:{[this.options.twoFaSecretFieldName]: decoded.newSecret}})
            }
            this.adminforth.auth.removeCustomCookie({response, name:'2FaTemporaryJWT'})
            this.adminforth.auth.setAuthCookie({expireInDays: decoded.rememberMeDays, response, username:decoded.userName, pk:decoded.pk})
            return { status: 'ok', allowedLogin: true }
          } else {
            return {error: 'Wrong or expired OTP code'}
          }
        } else {
          // login with confirming existing TOTP or Passkey
          let verified = null;
          if (body.usePasskey && this.options.passkeys) {
            // passkeys are enabled and user wants to use them
            const passkeysCookies = this.adminforth.auth.getCustomCookie({cookies: cookies, name: `passkeyLoginTemporaryJWT`});
            if (!passkeysCookies) {
              return { error: 'Passkey token is required' };
            }
            const decodedPasskeysCookies = await this.adminforth.auth.verify(passkeysCookies, 'tempLoginPasskeyChallenge', false);
            if (!decodedPasskeysCookies) {
              return { error: 'Invalid passkey' };
            }
            const res = await this.verifyPasskeyResponse(body.passkeyOptions, decoded.pk, decodedPasskeysCookies);
            if (res.ok && res.passkeyConfirmed) {
              verified = true;
            }
          } else {
            // user already has TOTP secret, get it
            this.connectors = this.adminforth.connectors
            const connector = this.connectors[this.authResource.dataSource];
            const user = await connector.getRecordByPrimaryKey(this.authResource, decoded.pk)
            verified = twofactor.verifyToken(user[this.options.twoFaSecretFieldName], body.code, this.options.timeStepWindow);
          }
          if (verified) {
            this.adminforth.auth.removeCustomCookie({response, name:'2FaTemporaryJWT'})
            this.adminforth.auth.setAuthCookie({expireInDays: decoded.rememberMeDays, response, username:decoded.userName, pk:decoded.pk})
            return { status: 'ok', allowedLogin: true }
          } else {
            return {error: 'Verification failed'}
          }
        }
      }
    })
    server.endpoint({
      method: 'POST',
      path: `/plugin/twofa/confirmLoginWithPasskey`,
      noAuth: true,
      handler: async ({ body, response, cookies, headers, requestUrl, query }) => {
        if ( this.options.passkeys.allowLoginWithPasskeys !== true ) {
          return { error: 'Login with passkeys is not allowed' };
        }

        const passkeyResponse = body.passkeyResponse;
        if (!passkeyResponse) {
          return { error: 'Passkey response is required' };
        }

        const totpTemporaryJWT = this.adminforth.auth.getCustomCookie({cookies: cookies, name: "passkeyLoginTemporaryJWT"});
        if (!totpTemporaryJWT) {
          return { error: 'Authentication session is expired. Please, try again' }
        }

        const decoded = await this.adminforth.auth.verify(totpTemporaryJWT, 'tempLoginPasskeyChallenge', false);
        if (!decoded) {
          return { error: 'Authentication session is expired. Please, try again' }
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

        const passkeyRecord = await this.adminforth.resource(this.options.passkeys.credentialResourceID).get([Filters.EQ(this.options.passkeys.credentialIdFieldName, credential_id)]);
        if (!passkeyRecord) {
          return { error: 'No registered passkey found, probably it was removed' };
        }

        const userPk = passkeyRecord[this.options.passkeys.credentialUserIdFieldName];
        if (!userPk) {
          return { error: 'User ID not found in passkey record' };
        }

        const userResourceId = this.adminforth.config.auth.usersResourceId;
        const usersResource = this.adminforth.config.resources.find(r => r.resourceId === userResourceId);
        const usersPrimaryKeyColumn = usersResource.columns.find((col) => col.primaryKey);
        const usersPrimaryKeyFieldName = usersPrimaryKeyColumn.name;
        const user = await this.adminforth.resource(userResourceId).get([Filters.EQ(usersPrimaryKeyFieldName, userPk)]);
        if (!user) {
          return { error: 'User not found' };
        }

        const verificationResult = await this.verifyPasskeyResponse(passkeyResponse, userPk, decoded);
        if (!verificationResult.ok || !verificationResult.passkeyConfirmed) {
          return { error: 'Passkey verification failed' };
        }
        const username = user[this.adminforth.config.auth.usernameField];

        const adminUser = { 
          dbUser: user,
          pk: user.id,
          username,
        };
        
        const toReturn = { allowedLogin: true, error: '' };

        await this.adminforth.restApi.processLoginCallbacks(adminUser, toReturn, response, {
          headers,
          cookies,
          requestUrl,
          query,
          body: {
            loginAllowedByPasskeyDirectSignIn: true
          },
        });

        if ( toReturn.allowedLogin === true ) {
          this.adminforth.auth.setAuthCookie({
            response,
            username,
            pk: user.id,
            expireInDays: this.options.passkeys.rememberDaysAfterPasskeyLogin ? this.options.passkeys.rememberDaysAfterPasskeyLogin : this.adminforth.config.auth.rememberMeDays,
          });
        }
        return toReturn;
      }
    }),
    server.endpoint({
      method: "GET",
      path: "/plugin/twofa/skip-allow",
      noAuth: true,
      handler: async ({ cookies }) => {
        const totpTemporaryJWT = this.adminforth.auth.getCustomCookie({
          cookies,
          name: `2FaTemporaryJWT`,
        });
        const decoded = await this.adminforth.auth.verify(
          totpTemporaryJWT,
          "temp2FA",
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
      method: "GET",
      path: "/plugin/twofa/skip-allow-modal",
      handler: async ({ adminUser }) => {
        if ( this.options.usersFilterToApply ) {
          const res = this.options.usersFilterToApply(adminUser);
          if ( res === false ) {
            return { skipAllowed: true };
          }
        }
        if ( this.options.usersFilterToAllowSkipSetup ) {
          const res = await this.checkIfSkipSetupAllowSkipVerify(adminUser);
          if ( res.skipAllowed === true ) {
            return { skipAllowed: true };
          }
        }
        return { skipAllowed: false };
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
      handler: async ({ body, adminUser, response, cookies }) => {
        const mode = body?.mode;

        const confirmationResult = body?.confirmationResult;
        const verificationResult = await this.verify(confirmationResult, {
          adminUser: adminUser,
          userPk: adminUser.pk, 
          cookies: cookies
        });
        if ( !verificationResult || !('ok' in verificationResult) ) {
          return { ok: false, error: 'Verification failed' };
        }

        const settingsOrigin = this.options.passkeys?.settings.expectedOrigin;
        const rp = {
          name: this.options.passkeys?.settings.rp.name || this.adminforth.config.customization.brandName,
          id: this.options.passkeys?.settings?.rp?.id || (new URL(settingsOrigin)).hostname,
        };
        const userResourceId = this.adminforth.config.auth.usersResourceId;
        const usersResource = this.adminforth.config.resources.find(r => r.resourceId === userResourceId);
        const usersPrimaryKeyColumn = usersResource.columns.find((col) => col.primaryKey);
        const usersPrimaryKeyFieldName = usersPrimaryKeyColumn.name;
        const userInfo = await this.adminforth.resource(userResourceId).get( [Filters.EQ(usersPrimaryKeyFieldName, adminUser.pk)] );
        const user = {
          id: adminUser.pk,
          name: userInfo[this.options.passkeys?.settings.user.nameField],
          displayName: userInfo[this.options.passkeys?.settings.user.displayNameField] ? userInfo[this.options.passkeys?.settings.user.displayNameField] : userInfo[this.options.passkeys?.settings.user.nameField],
        };
        const excludeCredentials = [];
        const temp = await this.adminforth.resource(this.options.passkeys.credentialResourceID).list([Filters.EQ(this.options.passkeys.credentialUserIdFieldName, adminUser.pk)]);
        for (const rec of temp) {
          if (rec.credential_id && rec.credential_id.length > 0) {
            const meta = JSON.parse(rec[this.options.passkeys.credentialMetaFieldName]);
            excludeCredentials.push({
              id: rec.credential_id,
              type: "public-key",
              transports: JSON.parse(meta.transports || '[]')
            });
          }
        }
        const options = await generateRegistrationOptions({
          rpName: rp.name,
          rpID: rp.id,
          userID: isoUint8Array.fromUTF8String(user.id),
          userName: user.name,
          userDisplayName: user.displayName,
          excludeCredentials,
          authenticatorSelection: {
            authenticatorAttachment: mode,
            requireResidentKey: this.options.passkeys?.settings.authenticatorSelection.requireResidentKey || true,
            userVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification || "required"
          },
        });
        const value = this.adminforth.auth.issueJWT({ "challenge": options.challenge, "user_id": adminUser.pk }, 'registerTempPasskeyChallenge', this.options.passkeys?.challengeValidityPeriod || '1m');
        this.adminforth.auth.setCustomCookie({response, payload: {name: "registerPasskeyTemporaryJWT", value: value, expiry: undefined, expirySeconds: 10 * 60, httpOnly: true}});
        return { ok: true, data: options };
      }
    });
    server.endpoint({
      method: 'POST',
      path: `/plugin/passkeys/finishRegisteringPasskey`,
      noAuth: false,
      handler: async ({body, adminUser, cookies }) => {
        const passkeysCookies = this.adminforth.auth.getCustomCookie({cookies: cookies, name: "registerPasskeyTemporaryJWT"});
        if (!passkeysCookies) {
          return { error: 'Passkey token is required' };
        }
        const decodedPasskeysCookies = await this.adminforth.auth.verify(passkeysCookies, 'registerTempPasskeyChallenge', false);
        if (!decodedPasskeysCookies) {
          return { error: 'Invalid passkey token' };
        }
        if (decodedPasskeysCookies.user_id !== adminUser.pk) {
          return { error: 'Invalid user' };
        }
        const settingsOrigin = this.options.passkeys?.settings.expectedOrigin;
        const expectedOrigin = body.origin;
        const expectedChallenge = decodedPasskeysCookies.challenge;
        const expectedRPID = this.options.passkeys?.settings?.rp?.id || (new URL(settingsOrigin)).hostname;
        const response = JSON.parse(body.credential);
        try {
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
            credentialBackedUp
          } = registrationInfo;
          const provider_name = aaguids[aaguid]?.name || 'Unknown provider';
          const credentialPublicKey = credential.publicKey;
          const credentialID = credential.id;

          const base64CredentialID = credentialID;
          const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);

          const credResource = this.adminforth.config.resources.find(r => r.resourceId === this.options.passkeys.credentialResourceID);
          if (!credResource) {
            throw new Error('Credential resource not found.');
          }
          await this.adminforth.createResourceRecord({
            resource: credResource, 
            record: {
              [this.options.passkeys.credentialIdFieldName]           : base64CredentialID,
              [this.options.passkeys.credentialUserIdFieldName]       : adminUser.pk,
              [this.options.passkeys.credentialMetaFieldName]         : JSON.stringify({
                public_key              : base64PublicKey,
                public_key_algorithm    : response.response.publicKeyAlgorithm,
                sign_count              : 0,
                transports              : JSON.stringify(response.response.transports),
                created_at              : new Date().toISOString(),
                last_used_at            : new Date().toISOString(),
                aaguid                  : aaguid,
                name                    : provider_name,
              }),
            },
            adminUser: adminUser
          });
        } catch (error) {
          console.error(error);
          return { error: 'Error registering passkey: ' + error.message };
        }
        return { ok: true };
      }
    });
    server.endpoint({
      method: 'POST',
      path: `/plugin/passkeys/signInRequest`,
      noAuth: true,
      handler: async ({ response }) => {
        try {
          const options = await generateAuthenticationOptions({
            rpID: this.options.passkeys?.settings.rp.id,
            userVerification: this.options.passkeys?.settings.authenticatorSelection.userVerification || "required"
          });
          const value = this.adminforth.auth.issueJWT({ "challenge": options.challenge }, 'tempLoginPasskeyChallenge', this.options.passkeys?.challengeValidityPeriod || '1m');
          this.adminforth.auth.setCustomCookie({response, payload: {name: `passkeyLoginTemporaryJWT`, value: value, expiry: undefined, expirySeconds: 10 * 60, httpOnly: true}});
          return { ok: true, data: options };
        } catch (e) {
          return { ok: false, error: e };
        }
      }
    });
    server.endpoint({
      method: 'GET',
      path: `/plugin/passkeys/getPasskeys`,
      noAuth: false,
      handler: async ({ adminUser }) => {
        let passkeys;
        try {
          passkeys = await this.adminforth.resource(this.options.passkeys.credentialResourceID).list( [Filters.EQ(this.options.passkeys.credentialUserIdFieldName, adminUser.pk)] );
        } catch (error) {
          return { ok: false, error: 'Error fetching passkeys: ' + error.message };
        }
        let dataToReturn = [];
        for (const pk of passkeys) {
          const parsedKey = JSON.parse(pk[this.options.passkeys.credentialMetaFieldName]);
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
    });
    server.endpoint({
      method: 'DELETE',
      path: `/plugin/passkeys/deletePasskey`,
      noAuth: false,
      handler: async ({body, adminUser }) => {
        const credentialID = body.passkeyId;
        if (!credentialID) {
          return { ok: false, error: 'Passkey ID is required' };
        }

        const passkeyRecord = await this.adminforth.resource(this.options.passkeys.credentialResourceID).get([Filters.EQ(this.options.passkeys.credentialIdFieldName, credentialID), Filters.EQ(this.options.passkeys.credentialUserIdFieldName, adminUser.pk)]);
        if (!passkeyRecord) {
          return { ok: false, error: 'Passkey not found' };
        }
        try {
          const credResource = this.adminforth.config.resources.find(r => r.resourceId === this.options.passkeys.credentialResourceID);
          if (!credResource) {
            throw new Error('Credential resource not found.');
          }
          const credResourcePKColumn = credResource.columns.find(c => c.primaryKey);
          if (!credResourcePKColumn) {
            throw new Error('Credential resource primary key not found.');
          }
          const credResourcePKName = credResourcePKColumn.name;
          const passkeyRecord = await this.adminforth.resource(this.options.passkeys.credentialResourceID).get([Filters.EQ(this.options.passkeys.credentialIdFieldName, credentialID), Filters.EQ(this.options.passkeys.credentialUserIdFieldName, adminUser.pk)]);
          if (!passkeyRecord) {
            return { ok: false, error: 'Passkey not found' };
          }
          await this.adminforth.deleteResourceRecord({
            resource: credResource,
            recordId: passkeyRecord[credResourcePKName],
            record: passkeyRecord,
            adminUser: adminUser,
          });
        } catch (error) {
          return { ok: false, error: 'Error deleting passkey: ' + error.message };
        }

        return { ok: true };
      }
    });
    server.endpoint({
      method: 'POST',
      path: `/plugin/passkeys/renamePasskey`,
      noAuth: false,
      handler: async ({body, adminUser }) => {
        const credentialID = body.passkeyId;
        const newName = body.newName;
        if (!credentialID) {
          return { ok: false, error: 'Passkey ID is required' };
        }
        if (!newName) {
          return { ok: false, error: 'New name is required' };
        }
        const credResource = this.adminforth.config.resources.find(r => r.resourceId === this.options.passkeys.credentialResourceID);
        if (!credResource) {
          throw new Error('Credential resource not found.');
        }
        const credResourcePKColumn = credResource.columns.find(c => c.primaryKey);
        if (!credResourcePKColumn) {
          throw new Error('Credential resource primary key not found.');
        }
        const credResourcePKName = credResourcePKColumn.name;
        const passkeyRecord = await this.adminforth.resource(this.options.passkeys.credentialResourceID).get([Filters.EQ(this.options.passkeys.credentialIdFieldName, credentialID), Filters.EQ(this.options.passkeys.credentialUserIdFieldName, adminUser.pk)]);
        if (!passkeyRecord) {
          return { ok: false, error: 'Passkey not found' };
        }
        const meta = JSON.parse(passkeyRecord[this.options.passkeys.credentialMetaFieldName]);
        meta.name = newName;
        const newRecord = { ...passkeyRecord, [this.options.passkeys.credentialMetaFieldName]: JSON.stringify(meta) };
        try {
          const credResource = this.adminforth.config.resources.find(r => r.resourceId === this.options.passkeys.credentialResourceID);
          if (!credResource) {
            throw new Error('Credential resource not found.');
          }
          await this.adminforth.updateResourceRecord({
            resource: credResource,
            recordId: passkeyRecord[credResourcePKName],
            oldRecord: passkeyRecord,
            record: newRecord,
            adminUser: adminUser
          });
        } catch (error) {
          return { ok: false, error: 'Error renaming passkey: ' + error.message };
        }
        return { ok: true };
      }
    });
    server.endpoint({
      method: 'POST',
      path: `/plugin/passkeys/checkIfUserHasPasskeys`,
      noAuth: true,
      handler: async ({ cookies }) => {
        if (!this.options.passkeys) {
          return { ok: false, hasPasskeys: false };
        }
        const totpTemporaryJWT = this.adminforth.auth.getCustomCookie({cookies: cookies, name: "2FaTemporaryJWT"});
        const decoded = await this.adminforth.auth.verify(totpTemporaryJWT, 'temp2FA');
        if (!decoded)
          return { ok: false, error:'Invalid token'}
        if (decoded.newSecret) {
          return { ok: true, hasPasskeys: false };
        }
        const passkeys = await this.adminforth.resource(this.options.passkeys.credentialResourceID).list( [Filters.EQ(this.options.passkeys.credentialUserIdFieldName, decoded.pk)] );
        if (passkeys && passkeys.length > 0) {
          return { ok: true, hasPasskeys: true };
        } else {
          return { ok: true, hasPasskeys: false };
        }
      }
    });
  }
}