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
  return new TotpService({ timeStepWindow: 1 }, userRepository, { auth });
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

const STEP_MS = 30_000;
const codeAt = (t, time) => {
  t.mock.timers.setTime(time);
  return twofactor.generateToken(SECRET).token;
};

test('a code confirms only one request, so a phished code can not be replayed', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000 * STEP_MS });
  const service = createService();
  const code = codeAt(t, 1_000 * STEP_MS);
  const results = await Promise.all([service.verifyUserCode('user-1', code), service.verifyUserCode('user-1', code)]);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal((await service.verifyUserCode('user-1', code)).code, TwoFactorErrorCode.INVALID);
  assert.equal((await service.verifyAdminUserCode({ pk: 'user-1' }, code)).code, TwoFactorErrorCode.INVALID);
  assert.deepEqual(await service.verifyUserCode('user-2', code), { ok: true });
});

test('after a code is used, older codes from the window are rejected and the next code is accepted', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000 * STEP_MS });
  const service = createService();
  const olderCode = codeAt(t, 1_000 * STEP_MS);
  const code = codeAt(t, 1_001 * STEP_MS);
  assert.deepEqual(await service.verifyUserCode('user-1', code), { ok: true });
  assert.equal((await service.verifyUserCode('user-1', olderCode)).code, TwoFactorErrorCode.INVALID);
  assert.deepEqual(await service.verifyUserCode('user-1', codeAt(t, 1_002 * STEP_MS)), { ok: true });
});
