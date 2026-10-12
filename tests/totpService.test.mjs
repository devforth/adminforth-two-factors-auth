import test from 'node:test';
import assert from 'node:assert/strict';
import twofactor from 'node-2fa';
import { TotpService } from '../dist/services/totpService.js';
import { TwoFactorErrorCode } from '../dist/utils/errors.js';

const SECRET = 'JBSWY3DPEHPK3PXP';
const userRepository = { getAuthUser: async (pk) => ({ pk }), getSecret: () => SECRET, getUserPk: (adminUser) => adminUser.pk };

function createService() {
  const jwts = new Map();
  const auth = {
    issueJWT: (payload, type) => {
      const token = `jwt-${jwts.size}`;
      jwts.set(token, { ...payload, type });
      return token;
    },
    verify: async (token, type) => (jwts.get(token)?.type === type ? jwts.get(token) : null),
  };
  return new TotpService({ timeStepWindow: 1 }, userRepository, auth);
}

test('limits code attempts of each user to stop brute force of a stolen session', async () => {
  const service = createService();
  for (let attempt = 0; attempt < 30; attempt++) {
    assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.INVALID);
  }
  assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.RATE_LIMITED);
  assert.equal((await service.verifyUserCode('user-2', 'wrong')).code, TwoFactorErrorCode.INVALID);
});

test('a correct code gives a token that confirms the code only for its user', async () => {
  const service = createService();
  const { verifiedCodeToken } = await service.verifyAdminUserCode({ pk: 'user-1' }, twofactor.generateToken(SECRET).token);
  assert.equal(await service.isVerifiedCodeToken(verifiedCodeToken, 'user-1'), true);
  assert.equal(await service.isVerifiedCodeToken(verifiedCodeToken, 'user-2'), false);
  assert.equal(await service.isVerifiedCodeToken('forged', 'user-1'), false);
});
