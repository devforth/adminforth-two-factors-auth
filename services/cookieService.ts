import type { IAdminForth, IAdminForthHttpResponse } from "adminforth";
import type { PluginOptions } from "../types.js";
import type { CookieList, HttpHeaders } from "../utils/types.js";
import crypto from 'crypto';

const TOTP_TEMP_COOKIE = "2FaTemporaryJWT";
const PASSKEY_LOGIN_TEMP_COOKIE = "passkeyLoginTemporaryJWT";
const REGISTER_PASSKEY_TEMP_COOKIE = "registerPasskeyTemporaryJWT";
const MFA_GRACE_COOKIE = "TempSkip2FA_Modal_JWT";
const AUTH_COOKIE = "jwt";

export type TotpTemporaryPayload = {
  userName: string;
  issuer?: string;
  pk: string;
  newSecret?: string;
  userCanSkipSetup?: boolean;
  sessionDuration?: string;
};

export type PasskeyLoginTemporaryPayload = {
  challenge: string;
};

export type RegisterPasskeyTemporaryPayload = {
  challenge: string;
  user_id: string;
};

export type MfaGracePayload = {
  hash: string;
  exp?: number;
};

export class CookieService {
  constructor(
    private readonly adminforth: IAdminForth,
    private readonly options: PluginOptions,
  ) {}

  public getAuthSessionCookie(cookies: CookieList): string | null {
    return this.adminforth.auth.getCustomCookie({ cookies, name: AUTH_COOKIE });
  }

  public setAuthCookie(opts: { response: IAdminForthHttpResponse; username: string; pk: string; expireInDuration: string }): void {
    this.adminforth.auth.setAuthCookie(opts);
  }

  public getTotpTemporary(cookies: CookieList): string | null {
    return this.adminforth.auth.getCustomCookie({ cookies, name: TOTP_TEMP_COOKIE });
  }

  public async verifyTotpTemporary(cookies: CookieList): Promise<TotpTemporaryPayload | null> {
    const jwt = this.getTotpTemporary(cookies);
    if (!jwt) return null;
    return this.adminforth.auth.verify(jwt, 'temp2FA') as Promise<TotpTemporaryPayload | null>;
  }

  public setTotpTemporary(response: IAdminForthHttpResponse, payload: TotpTemporaryPayload): void {
    const value = this.adminforth.auth.issueJWT(payload, 'temp2FA', this.options.passkeys?.challengeValidityPeriod || '1m');
    this.adminforth.auth.setCustomCookie({
      response,
      payload: { name: TOTP_TEMP_COOKIE, value, expiry: undefined, expirySeconds: 10 * 60, httpOnly: true },
    });
  }

  public removeTotpTemporary(response: IAdminForthHttpResponse): void {
    this.adminforth.auth.removeCustomCookie({ response, name: TOTP_TEMP_COOKIE });
  }

  public getPasskeyLoginTemporary(cookies: CookieList): string | null {
    return this.adminforth.auth.getCustomCookie({ cookies, name: PASSKEY_LOGIN_TEMP_COOKIE });
  }

  public async verifyPasskeyLoginTemporary(cookies: CookieList): Promise<PasskeyLoginTemporaryPayload | null> {
    const jwt = this.getPasskeyLoginTemporary(cookies);
    if (!jwt) return null;
    return this.adminforth.auth.verify(jwt, 'tempLoginPasskeyChallenge', false) as Promise<PasskeyLoginTemporaryPayload | null>;
  }

  public setPasskeyLoginTemporary(response: IAdminForthHttpResponse, challenge: string): void {
    const value = this.adminforth.auth.issueJWT({ challenge }, 'tempLoginPasskeyChallenge', this.options.passkeys?.challengeValidityPeriod || '1m');
    this.adminforth.auth.setCustomCookie({
      response,
      payload: { name: PASSKEY_LOGIN_TEMP_COOKIE, value, expiry: undefined, expirySeconds: 10 * 60, httpOnly: true },
    });
  }

  public getRegisterPasskeyTemporary(cookies: CookieList): string | null {
    return this.adminforth.auth.getCustomCookie({ cookies, name: REGISTER_PASSKEY_TEMP_COOKIE });
  }

  public async verifyRegisterPasskeyTemporary(cookies: CookieList): Promise<RegisterPasskeyTemporaryPayload | null> {
    const jwt = this.getRegisterPasskeyTemporary(cookies);
    if (!jwt) return null;
    return this.adminforth.auth.verify(jwt, 'registerTempPasskeyChallenge', false) as Promise<RegisterPasskeyTemporaryPayload | null>;
  }

  public setRegisterPasskeyTemporary(response: IAdminForthHttpResponse, payload: RegisterPasskeyTemporaryPayload): void {
    const value = this.adminforth.auth.issueJWT(payload, 'registerTempPasskeyChallenge', this.options.passkeys?.challengeValidityPeriod || '1m');
    this.adminforth.auth.setCustomCookie({
      response,
      payload: { name: REGISTER_PASSKEY_TEMP_COOKIE, value, expiry: undefined, expirySeconds: 10 * 60, httpOnly: true },
    });
  }

  public setMfaGrace(response: IAdminForthHttpResponse, hash: string): void {
    const value = this.adminforth.auth.issueJWT({ hash }, 'MfaGrace', `${this.options.stepUpMfaGracePeriodSeconds}s`);
    //TODO: fix ts-ignore after releasing new version of adminforth with updated types
    //@ts-ignore
    this.adminforth.auth.setCustomCookie({ response, payload: { name: MFA_GRACE_COOKIE, sessionBased: true, value, httpOnly: true } });
  }

  public async verifyMfaGrace(cookies: CookieList): Promise<MfaGracePayload | null> {
    const jwt = this.adminforth.auth.getCustomCookie({ cookies, name: MFA_GRACE_COOKIE });
    if (!jwt) return null;
    return this.adminforth.auth.verify(jwt, 'MfaGrace', false) as Promise<MfaGracePayload | null>;
  }

  private generateMfaGraceHash(headers: HttpHeaders, cookies: CookieList): string | null {
    const ip = this.adminforth.auth.getClientIp(headers);
    const userAgent = headers['user-agent'] || '';
    const acceptLanguage = headers['accept-language'] || '';
    const sessionCookie = this.getAuthSessionCookie(cookies);
    if (!process.env.ADMINFORTH_SECRET || !ip || !userAgent || !acceptLanguage || !sessionCookie) {
      console.error("❗️❗️❗️ Cannot set step-up MFA grace cookie: missing required request headers to identify client ❗️❗️❗️");
      return null;
    }

    return crypto.createHmac('sha256', process.env.ADMINFORTH_SECRET)
      .update(`${acceptLanguage}_${userAgent}_${ip}_${sessionCookie}`)
      .digest('hex');
  }

  public issueMfaGrace(opts: { headers?: HttpHeaders; response?: IAdminForthHttpResponse }, cookies: CookieList): void {
    if (!opts.response) {
      console.error("❗️❗️❗️ Cannot set step-up MFA grace cookie: response object is missing. You probably called verify() method without response parameter ❗️❗️❗️");
      return;
    }
    if (!opts.headers) {
      return;
    }

    const hash = this.generateMfaGraceHash(opts.headers, cookies);
    if (hash) {
      this.setMfaGrace(opts.response, hash);
    }
  }

  public async isMfaGraceValid(headers: HttpHeaders, cookies: CookieList, checkIfJWTAboutToExpire: boolean = false): Promise<boolean> {
    const hash = this.generateMfaGraceHash(headers, cookies);
    if (!hash) {
      return false;
    }
    const jwtVerificationResult = await this.verifyMfaGrace(cookies);
    if (!jwtVerificationResult) {
      return false;
    }
    if (checkIfJWTAboutToExpire && jwtVerificationResult.exp && (jwtVerificationResult.exp - ( Date.now() / 1000)) < 30 ) {
      console.error("❗️❗️❗️ Cannot validate step-up MFA grace cookie: token is expired or about to expire ❗️❗️❗️");
      return false;
    }
    return hash === jwtVerificationResult['hash'];
  }
}
