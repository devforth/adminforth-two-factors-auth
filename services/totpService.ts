import { RateLimiter, type AdminUser, type IAdminForth } from "adminforth";
import twofactor from 'node-2fa';
import type { PluginOptions } from "../types.js";
import { UserRepository } from "../repositories/userRepository.js";
import { TwoFactorErrorCode } from "../utils/errors.js";
import type { VerificationFailure, VerificationResult } from "../utils/types.js";

const CODE_ATTEMPT_RATE_LIMITS = ['30/1m', '300/1h', '1000/1d'];
const VERIFIED_CODE_JWT_TYPE = 'verifiedTotpCode';
const VERIFIED_CODE_TOKEN_TTL = '1m';

export class TotpService {
  private readonly codeAttemptLimiters = CODE_ATTEMPT_RATE_LIMITS.map((rate) => new RateLimiter(rate));

  constructor(
    private readonly options: PluginOptions,
    private readonly userRepository: UserRepository,
    private readonly adminforth: IAdminForth,
  ) {}

  public generateSecret(issuerName: string, userName: string): string {
    return twofactor.generateSecret({ name: issuerName, account: userName }).secret;
  }

  public verifySecret(secret: string, code: string): boolean {
    return Boolean(twofactor.verifyToken(secret, code, this.options.timeStepWindow));
  }

  public async verifyUserCode(userPk: string, code: string): Promise<VerificationResult> {
    const attemptsAllowed = await Promise.all(this.codeAttemptLimiters.map((limiter) => limiter.consume(userPk)));
    if (!attemptsAllowed.every(Boolean)) {
      return { error: "Too many attempts to enter the code. Try again later.", code: TwoFactorErrorCode.RATE_LIMITED };
    }

    const user = await this.userRepository.getAuthUser(userPk);
    if (!user) return { error: "User not found", code: TwoFactorErrorCode.USER_NOT_FOUND };

    const secret = this.userRepository.getSecret(user);
    if (!secret) return { error: "2FA is not set up for this user", code: TwoFactorErrorCode.NOT_SET_UP };

    return this.verifySecret(secret, code)
      ? { ok: true }
      : { error: "Wrong or expired OTP code", code: TwoFactorErrorCode.INVALID };
  }

  public async verifyAdminUserCode(adminUser: AdminUser, code: string): Promise<{ ok: true; verifiedCodeToken: string } | VerificationFailure> {
    const result = await this.verifyUserCode(this.userRepository.getUserPk(adminUser), code);
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
