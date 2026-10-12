import test from 'node:test';
import assert from 'node:assert/strict';
import { MfaRequestContext } from '../dist/services/mfaRequestContext.js';
const user = { pk: 'user-1' };

test('without external context normal browser verification is unaffected', async () => {
  const context = new MfaRequestContext();
  assert.equal(await context.verify(user, undefined, () => assert.fail('verification must not run')), undefined);
});

test('missing verification stops a CRUD hook before it can strip the error code', async () => {
  const context = new MfaRequestContext();
  let written = false;
  const result = await context.run(undefined, {}, async () => {
    await context.verify(user, undefined, async () => ({ error: 'Required', code: 'TWO_FACTOR_REQUIRED' }));
    written = true;
    return { ok: true };
  });
  assert.equal(written, false);
  assert.equal(result.code, 'TWO_FACTOR_REQUIRED');
});

test('a failed verification carries the action description for the confirmation page', async () => {
  const context = new MfaRequestContext();
  const result = await context.run(undefined, {}, async () => {
    await context.verify(user, 'Approve $100,000 bonus', async () => ({ error: 'Required', code: 'TWO_FACTOR_REQUIRED' }));
  });
  assert.deepEqual(result, { error: 'Required', code: 'TWO_FACTOR_REQUIRED', actionDescription: 'Approve $100,000 bonus' });
});

test('invalid TOTP or passkey cannot reach the mutation', async () => {
  for (const mode of ['totp', 'passkey']) {
    const context = new MfaRequestContext();
    const result = await context.run({ mode, result: 'invalid' }, {}, async () => {
      await context.verify(user, undefined, async () => ({ error: 'Invalid', code: 'TWO_FACTOR_INVALID' }));
      assert.fail('mutation must not execute');
    });
    assert.equal(result.code, 'TWO_FACTOR_INVALID');
  }
});

test('valid verification is reused only within the same request and user', async () => {
  const context = new MfaRequestContext();
  const token = { mode: 'totp', result: '123456' };
  const extra = { cookies: [{ key: 'session', value: 'browser' }] };
  let checks = 0;
  const verify = async (result, passedExtra) => { checks++; assert.equal(result, token); assert.equal(passedExtra, extra); return { ok: true }; };
  const run = () => context.run(token, extra, async () => {
    await context.verify(user, undefined, verify);
    await context.verify(user, undefined, verify);
    await context.verify({ pk: 'other-user' }, undefined, verify);
    return { ok: true };
  });
  await run();
  assert.equal(checks, 2);
  await run();
  assert.equal(checks, 4);
});

test('concurrent requests do not share verification or cookies', async () => {
  const context = new MfaRequestContext();
  const run = (token, cookie, code) => context.run(token, { cookie }, async () => {
    await context.verify(user, undefined, async (received, extra) => {
      await new Promise(resolve => setTimeout(resolve, 1));
      assert.equal(received, token);
      assert.equal(extra.cookie, cookie);
      return code ? { error: 'Required', code } : { ok: true };
    });
    return { ok: true };
  });
  const [accepted, rejected] = await Promise.all([run('valid', 'a'), run(undefined, 'b', 'TWO_FACTOR_REQUIRED')]);
  assert.equal(accepted.ok, true);
  assert.equal(rejected.code, 'TWO_FACTOR_REQUIRED');
});

test('unrelated execution errors propagate to MCP', async () => {
  const context = new MfaRequestContext();
  await assert.rejects(context.run(undefined, {}, async () => { throw new Error('DB error'); }), /DB error/);
});
