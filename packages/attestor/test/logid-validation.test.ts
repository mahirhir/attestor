// Log IDs arrive inside log responses, so on any path that reaches a hostile
// or impersonated log they are attacker-controlled. `pinRekorKey` interpolates
// one into a pin filename and uses the result for an existence check that can
// skip both the key fetch and the trust gate, so a malformed ID must never
// reach a path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLogId, rekorKeyPinName, UntrustedRekorKeyError } from '../src/rekor.ts';

const VALID = 'a'.repeat(64);

test('isLogId accepts only a lowercase 64-hex digest', () => {
  assert.equal(isLogId(VALID), true);
  assert.equal(isLogId('0123456789abcdef'.repeat(4)), true);

  for (const bad of [
    '../../etc/passwd',
    '../rekor-pub',
    'a/b',
    'a\\b',
    `${VALID}/..`,
    VALID.toUpperCase(), // case matters: two spellings would be two pins for one log
    'a'.repeat(63),
    'a'.repeat(65),
    'g'.repeat(64), // not hex
    '',
    undefined,
    null,
    123,
  ]) {
    assert.equal(isLogId(bad), false, `rejected: ${JSON.stringify(bad)}`);
  }
});

test('rekorKeyPinName refuses to build a path segment from a malformed log ID', () => {
  assert.equal(rekorKeyPinName(VALID), `rekor-pub-${VALID}.pem`);

  for (const bad of ['../../evil', '../rekor-pub', 'a/b', `${VALID}/..`, '']) {
    assert.throws(
      () => rekorKeyPinName(bad),
      UntrustedRekorKeyError,
      `must refuse ${JSON.stringify(bad)}`,
    );
  }
});

test('a pin filename never escapes its directory', () => {
  // The property the two tests above exist to protect, stated once directly.
  for (const id of [VALID, '0'.repeat(64)]) {
    const name = rekorKeyPinName(id);
    assert.equal(name.includes('/'), false);
    assert.equal(name.includes('\\'), false);
    assert.equal(name.includes('..'), false);
  }
});
