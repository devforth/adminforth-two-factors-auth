import test from 'node:test';
import assert from 'node:assert/strict';
import { TotpService } from '../dist/services/totpService.js';
import { TwoFactorErrorCode } from '../dist/utils/errors.js';

const userRepository = { getAuthUser: async (pk) => ({ pk }), getSecret: () => 'JBSWY3DPEHPK3PXP' };

test('limits code attempts of each user to stop brute force of a stolen session', async () => {
  const service = new TotpService({ timeStepWindow: 1 }, userRepository);
  for (let attempt = 0; attempt < 30; attempt++) {
    assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.INVALID);
  }
  assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.RATE_LIMITED);
  assert.equal((await service.verifyUserCode('user-2', 'wrong')).code, TwoFactorErrorCode.INVALID);
});
