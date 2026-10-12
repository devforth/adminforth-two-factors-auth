import type { AdminUser } from "adminforth";
import twofactor from 'node-2fa';
import type { PluginOptions } from "../types.js";
import { UserRepository } from "../repositories/userRepository.js";
import { TwoFactorErrorCode } from "../utils/errors.js";
import type { VerificationResult } from "../utils/types.js";

export class TotpService {
  constructor(
    private readonly options: PluginOptions,
    private readonly userRepository: UserRepository,
  ) {}

  public generateSecret(issuerName: string, userName: string): string {
    return twofactor.generateSecret({ name: issuerName, account: userName }).secret;
  }

  public verifySecret(secret: string, code: string): boolean {
    return Boolean(twofactor.verifyToken(secret, code, this.options.timeStepWindow));
  }

  public async verifyUserCode(userPk: string, code: string): Promise<VerificationResult> {
    const user = await this.userRepository.getAuthUser(userPk);
    if (!user) return { error: "User not found", code: TwoFactorErrorCode.USER_NOT_FOUND };

    const secret = this.userRepository.getSecret(user);
    if (!secret) return { error: "2FA is not set up for this user", code: TwoFactorErrorCode.NOT_SET_UP };

    return this.verifySecret(secret, code)
      ? { ok: true }
      : { error: "Wrong or expired OTP code", code: TwoFactorErrorCode.INVALID };
  }

  public async verifyAdminUserCode(adminUser: AdminUser, code: string): Promise<VerificationResult> {
    return this.verifyUserCode(this.userRepository.getUserPk(adminUser), code);
  }

  public async saveSecret(userPk: string, secret: string): Promise<void> {
    await this.userRepository.updateSecret(userPk, secret);
  }
}
