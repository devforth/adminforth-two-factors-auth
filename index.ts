import {  AdminForthPlugin, suggestIfTypo, HttpExtra } from "adminforth";
import type { AdminForthResource, AdminUser, IAdminForth, IHttpServer, IAdminForthAuth, IAdminForthHttpResponse } from "adminforth";
import  { PluginOptions } from "./types.js"
import { PasskeyService } from "./services/passkeyService.js";
import { TotpService } from "./services/totpService.js";
import { verifyMfaConfirmation, type VerifyOptions } from "./services/verifyMfaConfirmation.js";
import { CookieService } from "./services/cookieService.js";
import { UserRepository } from "./repositories/userRepository.js";
import { registerPasskeyEndpoints } from "./endpoints/registerPasskeyEndpoints.js";
import { registerTwoFaEndpoints } from "./endpoints/registerTwoFaEndpoints.js";
import { createPasskeyHandlers } from "./handlers/createPasskeyHandlers.js";
import { createTwoFaHandlers } from "./handlers/createTwoFaHandlers.js";
import { parsePeriod } from "./utils/parsePeriod.js";
import crypto from 'crypto';

export default class TwoFactorsAuthPlugin extends AdminForthPlugin {
  options: PluginOptions;
  adminforth: IAdminForth;
  authResource: AdminForthResource;
  adminForthAuth: IAdminForthAuth;
  passkeyService: PasskeyService;
  totpService: TotpService;
  cookieService: CookieService;
  userRepository: UserRepository;
  private ctx: any;

  constructor(options: PluginOptions) {
    super(options, import.meta.url);
    this.options = options;
    this.shouldHaveSingleInstancePerWholeApp = () => true;
  }

  instanceUniqueRepresentation(pluginOptions: any) : string {
    return `single`;
  }

  public async checkIfSkipSetupAllowSkipVerify(adminUser: AdminUser): Promise<{ skipAllowed: boolean }> {
    if (this.options.usersFilterToAllowSkipSetup) {
      const res = this.options.usersFilterToAllowSkipSetup(adminUser); // recieve result of usersFilterToAllowSkipSetup
      if (res === false) { // if false, user is not allowed to skip anyway, so doesn't matter if they have 2FA set up or not
        return { skipAllowed: false };
      }
      
      //recieve user's record
      const userPkFieldName = this.userRepository.getUserPkField();
      const userRecord = await this.userRepository.getAuthUser(adminUser.pk);

      //check if user has 2FA set up
      const users2FASecret = this.userRepository.getSecret(userRecord);
      //check if user has any passkeys registered
      const userHasPasskeys = await this.passkeyService.hasPasskeysForUser(adminUser.dbUser[userPkFieldName]);

      // If user has either 2FA secret or any passkeys, they cannot skip
      if (users2FASecret || userHasPasskeys) {
        return { skipAllowed: false };
      }
      return { skipAllowed: res };
    }
    return { skipAllowed: false };
  }

  private pending = new Map<string, (value: any) => void>();

  private waitForResponse(id: string, timeoutMs: number): Promise<any> {
    return new Promise((resolve) => {
      let timeout: ReturnType<typeof setTimeout>;
      const cleanup = () => {
        clearTimeout(timeout);
        this.pending.delete(id);
      };
      timeout = setTimeout(() => {
        cleanup();
        resolve({ ok: false, error: 'Verification timed out' });
      }, timeoutMs);
      this.pending.set(id, (value: any) => {
        cleanup();
        resolve(value);
      });
    });
  }

  private resolveResponse(id: string, data: any) {
    const resolve = this.pending.get(id);
    if (resolve) {
      resolve(data);
    }
  }

  public async verifyAuto(adminUser: AdminUser) {
    const sessionId = crypto.randomUUID();
    const jwt = this.adminforth.auth.issueJWT({sessionId, adminUserPk: adminUser.pk}, 'auto2FA', '5m');
    const resultPromise = this.waitForResponse(jwt, 5 * 60 * 1000);

    this.adminforth.websocket.publish(`/user2fa/${adminUser.pk}`, { sessionId: jwt });

    const result = await resultPromise;

    this.adminforth.websocket.publish(`/user2fa/${adminUser.pk}-resolve`, { sessionId: jwt });

    return result;
  }

  public async verify(
    confirmationResult: Record<string, any>,
    opts?: VerifyOptions
  ): Promise<{ ok: true } | { error: string }> {
    return verifyMfaConfirmation(this.ctx, confirmationResult, opts);
  }

  modifyResourceConfig(adminforth: IAdminForth, resourceConfig: AdminForthResource) {
    super.modifyResourceConfig(adminforth, resourceConfig);
    this.adminforth = adminforth;
    this.adminForthAuth = adminforth.auth;
    this.userRepository = new UserRepository(this.adminforth, this.options);
    this.cookieService = new CookieService(this.adminforth, this.options);
    this.totpService = new TotpService(this.options, this.userRepository);
    this.passkeyService = new PasskeyService(this.options, this.adminforth, this.userRepository, undefined, this.cookieService);
    this.ctx = {
      adminforth: this.adminforth,
      options: this.options,
      authResource: resourceConfig,
      userRepository: this.userRepository,
      totpService: this.totpService,
      passkeyService: this.passkeyService,
      cookieService: this.cookieService,
      verifyMfaConfirmation: (confirmationResult, opts) => verifyMfaConfirmation(this.ctx, confirmationResult, opts),
      checkIfSkipSetupAllowSkipVerify: this.checkIfSkipSetupAllowSkipVerify.bind(this),
      autoVerify: {
        verifyAuto: this.verifyAuto.bind(this),
        resolveResponse: this.resolveResponse.bind(this),
      },
    };
    const suggestionPeriod = parsePeriod(this.options.passkeys?.suggestionPeriod || "5d");
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
        isVisible: (adminUser: AdminUser) => {
          const secret = this.userRepository.getSecret(adminUser.dbUser)
          if (!secret || secret.length === 0) {
            return false;
          }
          return true;
        }
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

      if (!this.options.passkeys.keyValueAdapter) {
        throw new Error('Passkeys keyValueAdapter is required');
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
      async({ adminUser, response, adminforth, extra, sessionDuration }: { adminUser: AdminUser, response: IAdminForthHttpResponse, adminforth: IAdminForth, extra?: HttpExtra,  sessionDuration?: string} )=> {
        if ( extra?.meta?.loginAllowedByPasskeyDirectSignIn === true) {
          return { body: { loginAllowed: true }, ok: true };
        }
        const secret = this.userRepository.getSecret(adminUser.dbUser)
        const userName = adminUser.dbUser[adminforth.config.auth.usernameField]
        const brandName = adminforth.config.customization.brandName;
        const brandNameSlug = adminforth.config.customization.brandNameSlug;
        const issuerName = (this.options.customBrandPrefix && this.options.customBrandPrefix.trim())
        ? this.options.customBrandPrefix.trim()
        : brandName;
        const userPk = this.userRepository.getUserPk(adminUser)
        let newSecret = null;

        const userNeeds2FA = this.options.usersFilterToApply ? this.options.usersFilterToApply(adminUser) : true;
        if (!userNeeds2FA){
          return { body:{loginAllowed: true}, ok: true}
        }
        const userCanSkipSetup = this.options.usersFilterToAllowSkipSetup ? this.options.usersFilterToAllowSkipSetup(adminUser) : false;

        if (!secret){
          newSecret = this.totpService.generateSecret(issuerName, userName);
          this.cookieService.setTotpTemporary(response, {userName, newSecret, issuer:issuerName, pk:userPk, userCanSkipSetup, sessionDuration });

          return {
            body:{
              loginAllowed: false,
              redirectTo: secret ? '/confirm2fa' : '/setup2fa',
            },
            ok: true
          }

        } else {
          this.cookieService.setTotpTemporary(response, {userName, issuer:issuerName, pk:userPk, userCanSkipSetup, sessionDuration });

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
    registerTwoFaEndpoints(server, createTwoFaHandlers(this.ctx));
    registerPasskeyEndpoints(server, createPasskeyHandlers(this.ctx));
  }
}
