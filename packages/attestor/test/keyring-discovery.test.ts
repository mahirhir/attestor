// Regression: pinned Rekor log keys live in the same directory as recorder
// private keys. They are public keys, so if recorder key discovery picks one
// up, loadKey() fails inside OpenSSL on the next process start rather than
// returning a key. Pins are written after key generation, so the newest-first
// active-key rule selects a pin in preference to the real signing key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKey, keysDir, listKeyIds, loadKey } from '../src/keys.ts';
import { rekorKeyPinName } from '../src/rekor.ts';
import { fakeRekor, tmp } from './helpers.ts';

test('recorder key discovery ignores keyed and legacy Rekor pins', () => {
  const home = tmp('attestor-keyring-');
  const recorder = generateKey(home);
  const dir = keysDir(home);
  mkdirSync(dir, { recursive: true });

  const log = fakeRekor();
  const logId = 'a'.repeat(64);

  // Written after the recorder key, so mtime order would otherwise prefer them.
  writeFileSync(join(dir, rekorKeyPinName(logId)), log.publicPem);
  writeFileSync(join(dir, 'rekor-pub.pem'), log.publicPem);

  const ids = listKeyIds(home);
  assert.deepEqual(ids, [recorder.keyId], 'only the recorder key is a key id');
  assert.equal(
    ids.some((id) => id.startsWith('rekor-pub')),
    false,
    'no Rekor pin is offered as a recorder key',
  );

  // The real failure this guards: the active key is the last id, so a pin
  // leaking into the list makes loadKey() throw on an unrelated public key.
  assert.equal(loadKey(home).keyId, recorder.keyId);
});
