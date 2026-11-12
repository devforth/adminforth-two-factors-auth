import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveVerifyAutoBodySchema } from '../dist/endpoints/validation.js';

test('resolveVerifyAuto accepts a cancelled confirmation, so the handler can release the waiting request', () => {
  // TwoFAModal sends confirmationResult: undefined on Cancel, JSON drops it
  const cancelBody = JSON.parse(JSON.stringify({ confirmationResult: undefined, sessionsIds: ['session'] }));
  assert.equal(resolveVerifyAutoBodySchema.safeParse(cancelBody).success, true);
});
