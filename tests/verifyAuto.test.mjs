import test from 'node:test';
import assert from 'node:assert/strict';
import { runWithRequestContext } from 'adminforth';
import TwoFactorsAuthPlugin from '../dist/index.js';
import { MfaRequestContext } from '../dist/services/mfaRequestContext.js';

const user = { pk: 'user-1' };

function fakePlugin({ verifyResult, delivered }) {
  const published = [];
  const plugin = Object.assign(Object.create(TwoFactorsAuthPlugin.prototype), {
    pending: new Map(),
    mfaRequestContext: new MfaRequestContext(),
    verify: async () => verifyResult,
    adminforth: {
      auth: { issueJWT: () => 'jwt' },
      websocket: { publish: async (topic) => { published.push(topic); return delivered; } },
    },
  });
  return { plugin, published };
}

const inTab = (fn) => runWithRequestContext({ websocketClientId: 'tab-1' }, fn);

test('verifyAuto fails fast when no browser tab received the prompt', { timeout: 1000 }, async () => {
  const { plugin } = fakePlugin({ verifyResult: { error: 'Required', code: 'TWO_FACTOR_REQUIRED' }, delivered: 0 });

  const result = await inTab(() => plugin.verifyAuto(user));

  assert.equal(result.ok, false);
  assert.equal(result.code, 'VERIFICATION_DELIVERY_FAILED');
});

test('verifyAuto does not prompt users who do not need 2FA', async () => {
  const { plugin, published } = fakePlugin({ verifyResult: { ok: true }, delivered: 1 });

  assert.deepEqual(await inTab(() => plugin.verifyAuto(user)), { ok: true });
  assert.deepEqual(published, []);
});

test('verifyAuto keeps waiting for the tab on an older core whose publish resolves nothing', { timeout: 1000 }, async () => {
  const { plugin } = fakePlugin({ verifyResult: { error: 'Required', code: 'TWO_FACTOR_REQUIRED' }, delivered: undefined });

  const pending = inTab(() => plugin.verifyAuto(user));
  await new Promise(setImmediate);
  plugin.resolveResponse('jwt', { ok: true });

  assert.deepEqual(await pending, { ok: true });
});
