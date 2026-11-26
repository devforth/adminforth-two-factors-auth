import { RateLimiter, type AdminUser, type HttpExtra, type IAdminForth, type RateLimitString } from "adminforth";
import { Secret, TOTP } from "otpauth";
import type { PluginOptions } from "../types.js";
import { UserRepository } from "../repositories/userRepository.js";
import { TwoFactorErrorCode } from "../utils/errors.js";
import type { VerificationFailure, VerificationResult } from "../utils/types.js";

const DEFAULT_TOTP_RATE_LIMIT: RateLimitString[] = ['30/1m', '300/1h', '1000/1d'];
const VERIFIED_CODE_JWT_TYPE = 'verifiedTotpCode';
const VERIFIED_CODE_TOKEN_TTL = '1m';
const RATE_LIMITED_ERROR = "Too many attempts to enter the code. Try again later.";
// codes and secrets are shown in groups, "123 456" or "ABCD-EFGH"; node-2fa stripped them from both
const SEPARATORS = /\W+/g;

export class TotpService {
  private readonly codeAttemptLimiters: RateLimiter[];
  private readonly lastUsedCodeSteps = new Map<string, number>();

  constructor(
    private readonly options: PluginOptions,
    private readonly userRepository: UserRepository,
    private readonly adminforth: IAdminForth,
  ) {
    this.codeAttemptLimiters = (options.totpRateLimit ?? DEFAULT_TOTP_RATE_LIMIT).map((rate) => new RateLimiter(rate));
  }

  public generateSecret(): string {
    return new Secret().base32;
  }

  public verifySecret(secret: string, code: string): boolean {
    return this.findCodeStep(secret, code) !== null;
  }

  private findCodeStep(secret: string, code: string): number | null {
    // the code comes from a request body, where it can be missing or not a string
    if (typeof code !== 'string') {
      return null;
    }
    // one clock reading for the check and the step, so they agree at a step boundary
    const timestamp = Date.now();
    const delta = TOTP.validate({
      token: code.replace(SEPARATORS, ''),
      secret: Secret.fromBase32(secret.replace(SEPARATORS, '')),
      window: this.options.timeStepWindow,
      timestamp,
    });
    return delta === null ? null : TOTP.counter({ timestamp }) + delta;
  }

  public async verifyUserCode(userPk: string, code: string, extra?: HttpExtra): Promise<VerificationResult> {
    const attemptsAllowed = await Promise.all(this.codeAttemptLimiters.map((limiter) => limiter.consume(userPk)));
    if (!attemptsAllowed.every(Boolean)) {
      return { error: RATE_LIMITED_ERROR, code: TwoFactorErrorCode.RATE_LIMITED };
    }

    const user = await this.userRepository.getAuthUser(userPk);
    if (!user) return { error: "User not found", code: TwoFactorErrorCode.USER_NOT_FOUND };

    const secret = this.userRepository.getSecret(user);
    if (!secret) return { error: "2FA is not set up for this user", code: TwoFactorErrorCode.NOT_SET_UP };

    const hookParams = { pk: userPk, dbUser: user, adminforth: this.adminforth, extra };
    const otpCheck = await this.options.beforeOtpCheck?.(hookParams);
    if (otpCheck && !otpCheck.allowed) {
      await this.refundCodeAttempt(userPk);
      return { error: otpCheck.error ?? RATE_LIMITED_ERROR, code: TwoFactorErrorCode.RATE_LIMITED };
    }

    const step = this.findCodeStep(secret, code);
    if (step === null) {
      await this.options.onOtpFailed?.(hookParams);
      return { error: "Wrong or expired OTP code", code: TwoFactorErrorCode.INVALID };
    }

    if (step <= (this.lastUsedCodeSteps.get(userPk) ?? -Infinity)) {
      return { error: "This code has already been used. Wait for the next one.", code: TwoFactorErrorCode.INVALID };
    }
    this.lastUsedCodeSteps.set(userPk, step);
    await this.refundCodeAttempt(userPk);
    await this.options.onOtpSucceeded?.(hookParams);
    return { ok: true };
  }

  // attempt is consumed before the check so parallel requests can't bypass the limit, and given back when the code is correct
  // or rejected by beforeOtpCheck, so an attacker whose IP the app blocked can't use up the user's limit and lock the user out
  private async refundCodeAttempt(userPk: string): Promise<void> {
    await Promise.all(this.codeAttemptLimiters.map((limiter) => limiter.rateLimiter.reward(userPk, 1)));
  }

  public async verifyAdminUserCode(adminUser: AdminUser, code: string, extra: HttpExtra): Promise<{ ok: true; verifiedCodeToken: string } | VerificationFailure> {
    const result = await this.verifyUserCode(this.userRepository.getUserPk(adminUser), code, extra);
    if ('error' in result) return result;
    return { ok: true, verifiedCodeToken: this.adminforth.auth.issueJWT({ pk: adminUser.pk }, VERIFIED_CODE_JWT_TYPE, VERIFIED_CODE_TOKEN_TTL) };
  }

  public async isVerifiedCodeToken(token: string, userPk: string): Promise<boolean> {
    const payload = await this.adminforth.auth.verify(token, VERIFIED_CODE_JWT_TYPE, false);
    return payload?.pk === userPk;
  }

  public async saveSecret(userPk: string, secret: string): Promise<void> {
    await this.userRepository.updateSecret(userPk, secret);
  }
}
