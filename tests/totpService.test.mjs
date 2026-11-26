import test from 'node:test';
import assert from 'node:assert/strict';
import { TotpService } from '../dist/services/totpService.js';
import { TwoFactorErrorCode } from '../dist/utils/errors.js';

const SECRET = 'JBSWY3DPEHPK3PXP';
const STEP_MS = 30_000;
// codes of SECRET at the steps 1000-1002, computed with an independent RFC 4226 implementation
const CODES = { 1000: '120699', 1001: '082801', 1002: '676083' };
const userRepository = { getAuthUser: async (pk) => ({ pk }), getSecret: () => SECRET, getUserPk: (adminUser) => adminUser.pk };

function createService(options = {}) {
  const jwts = new Map();
  const auth = {
    issueJWT: (payload, type) => {
      const token = `jwt-${jwts.size}`;
      jwts.set(token, { ...payload, type });
      return token;
    },
    verify: async (token, type) => (jwts.get(token)?.type === type ? jwts.get(token) : null),
  };
  return new TotpService({ timeStepWindow: 1, ...options }, userRepository, { auth });
}

test('limits code attempts of each user to stop brute force of a stolen session', async () => {
  const service = createService();
  for (let attempt = 0; attempt < 30; attempt++) {
    assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.INVALID);
  }
  assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.RATE_LIMITED);
  assert.equal((await service.verifyUserCode('user-2', 'wrong')).code, TwoFactorErrorCode.INVALID);
});

test('uses totpRateLimit from plugin options instead of the default limits', async () => {
  const service = createService({ totpRateLimit: ['3/1m'] });
  for (let attempt = 0; attempt < 3; attempt++) {
    assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.INVALID);
  }
  assert.equal((await service.verifyUserCode('user-1', 'wrong')).code, TwoFactorErrorCode.RATE_LIMITED);
});

test('calls onOtpFailed for a wrong code and onOtpSucceeded for a correct one, but not for rate limited or reused codes', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000 * 30_000 });
  const calls = [];
  const extra = { headers: { 'x-forwarded-for': '1.2.3.4' } };
  const service = createService({
    totpRateLimit: ['2/1m'],
    onOtpFailed: async (params) => { calls.push(['failed', params]); },
    onOtpSucceeded: async (params) => { calls.push(['succeeded', params]); },
  });
  const code = CODES[1000];

  await service.verifyUserCode('user-1', 'wrong', extra);
  await service.verifyUserCode('user-1', code, extra);
  await service.verifyUserCode('user-1', code, extra);
  await service.verifyUserCode('user-1', 'wrong', extra);

  assert.deepEqual(calls.map(([event]) => event), ['failed', 'succeeded']);
  assert.equal(calls[0][1].pk, 'user-1');
  assert.deepEqual(calls[0][1].dbUser, { pk: 'user-1' });
  assert.equal(calls[0][1].extra, extra);
});

test('beforeOtpCheck rejects an attempt without checking the code and without using up the user limit', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000 * 30_000 });
  const calls = [];
  const extra = { headers: { 'x-forwarded-for': '1.2.3.4' } };
  let allowed = false;
  const service = createService({
    totpRateLimit: ['1/1m'],
    beforeOtpCheck: async (params) => {
      calls.push(['before', params]);
      return allowed ? { allowed } : { allowed, error: 'Too many wrong codes from your IP' };
    },
    onOtpFailed: async (params) => { calls.push(['failed', params]); },
  });
  const rejected = { error: 'Too many wrong codes from your IP', code: TwoFactorErrorCode.RATE_LIMITED };

  assert.deepEqual(await service.verifyUserCode('user-1', CODES[1000], extra), rejected);
  assert.deepEqual(await service.verifyUserCode('user-1', 'wrong', extra), rejected);
  allowed = true;
  assert.equal((await service.verifyUserCode('user-1', 'wrong', extra)).code, TwoFactorErrorCode.INVALID);
  assert.equal((await service.verifyUserCode('user-1', 'wrong', extra)).code, TwoFactorErrorCode.RATE_LIMITED);

  assert.deepEqual(calls.map(([event]) => event), ['before', 'before', 'before', 'failed']);
  assert.equal(calls[0][1].pk, 'user-1');
  assert.equal(calls[0][1].extra, extra);
});

test('a correct code gives a token that confirms the code only for its user', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_000 * STEP_MS });
  const service = createService();
  const { verifiedCodeToken } = await service.verifyAdminUserCode({ pk: 'user-1' }, CODES[1000]);
  assert.equal(await service.isVerifiedCodeToken(verifiedCodeToken, 'user-1'), true);
  assert.equal(await service.isVerifiedCodeToken(verifiedCodeToken, 'user-2'), false);
  assert.equal(await service.isVerifiedCodeToken('forged', 'user-1'), false);
});

const codeAt = (t, time) => {
  t.mock.timers.setTime(time);
  return CODES[time / STEP_MS];
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

// the key of the RFC 4226 and RFC 6238 test vectors, "12345678901234567890" in base32
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('RFC 6238 SHA-1 codes are accepted at their times, including the ones with leading zeros', (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 0 });
  const service = createService({ timeStepWindow: 0 });
  const vectors = [[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130']];
  for (const [seconds, code] of vectors) {
    t.mock.timers.setTime(seconds * 1000);
    assert.equal(service.verifySecret(RFC_SECRET, code), true);
  }
});

// node-2fa cut the code to its last characters when the truncated 31-bit value had fewer than 6 digits
// (it gave "5" instead of "092555"), so the code of an authenticator app never matched: 1 step in 21474
test('a code whose truncated value is below 100000 is zero padded and accepted', (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 0 });
  const service = createService({ timeStepWindow: 0 });
  for (const [step, code] of [[10281, '092555'], [732066, '007261'], [2011430, '000835']]) {
    t.mock.timers.setTime(step * STEP_MS);
    assert.equal(service.verifySecret(RFC_SECRET, code), true);
    assert.equal(service.verifySecret(RFC_SECRET, String(Number(code))), false);
  }
});

test('timeStepWindow is the number of steps before and after the current one which are accepted', (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_001 * STEP_MS });
  const exact = createService({ timeStepWindow: 0 });
  const lenient = createService({ timeStepWindow: 1 });

  assert.deepEqual([CODES[1000], CODES[1001], CODES[1002]].map((code) => exact.verifySecret(SECRET, code)), [false, true, false]);
  assert.deepEqual([CODES[1000], CODES[1001], CODES[1002]].map((code) => lenient.verifySecret(SECRET, code)), [true, true, true]);
  assert.equal(lenient.verifySecret(SECRET, '000000'), false);
});

test('a code or a secret written in groups is accepted, a missing or malformed code is a wrong code', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: 1_001 * STEP_MS });
  const service = createService({ timeStepWindow: 0 });
  assert.equal(service.verifySecret(SECRET, '082 801'), true);
  assert.equal(service.verifySecret(SECRET, '082-801'), true);
  assert.equal(service.verifySecret('jbsw-y3dp ehpk-3pxp\n', '082801'), true);
  for (const code of [undefined, null, 82801, '', '08280', '0828011', 'abcdef']) {
    assert.equal((await service.verifyUserCode(`user-${code}`, code)).code, TwoFactorErrorCode.INVALID);
  }
});

test('generated secrets are random base32 keys of 160 bits which authenticator apps accept', () => {
  const service = createService();
  const secrets = new Set(Array.from({ length: 50 }, () => service.generateSecret()));
  assert.equal(secrets.size, 50);
  for (const secret of secrets) {
    assert.match(secret, /^[A-Z2-7]{32}$/);
  }
});
