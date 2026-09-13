// A legacy single-file Rekor pin (`rekor-pub.pem`) predates the keyring and
// carries no log ID, so standing it in for an anchor whose logID it does not
// match is unsound. Both directions are covered, because a gate that simply
// disabled the fallback would satisfy the first test alone.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { attestorHome, keysDir } from '../src/keys.ts';
import { getSpkiFingerprint } from '../src/rekor.ts';
import { verifyLedger } from '../src/verify.ts';
import { buildAnchoredLedger, fakeRekor } from './helpers.ts';

const setFindings = (f: { check: string; reason: string }[]) =>
  f.filter((x) => x.check === 'ANCHOR' && /SET signature invalid/i.test(x.reason));

/**
 * Leave the host with a pre-keyring pin only: one `rekor-pub.pem` and no
 * keyed pin for this anchor's log. Without this the fixture's own keyed pin
 * satisfies the lookup and the legacy fallback is never reached, so a test
 * written over the default fixture cannot observe the fallback at all.
 */
function hostHasOnlyLegacyPin(pem: string): void {
  const dir = keysDir(attestorHome());
  for (const f of readdirSync(dir)) {
    if (f.startsWith('rekor-pub-') && f.endsWith('.pem')) rmSync(join(dir, f));
  }
  writeFileSync(join(dir, 'rekor-pub.pem'), pem);
}

test('an unrelated legacy pin is not applied to this anchor', async () => {
  const { ledgerDir, rekor } = buildAnchoredLedger({ calls: 1 });

  // The shape left behind by a pin taken before a log-key rotation, or a
  // rogue pin: a real key, but not the one that signed this anchor.
  const other = fakeRekor();
  assert.notEqual(getSpkiFingerprint(other.publicPem), rekor.logId);
  hostHasOnlyLegacyPin(other.publicPem);

  const report = await verifyLedger(ledgerDir);

  // Applying the unrelated key yields an invalid-SET finding, which reads as
  // tamper on a ledger that is intact.
  assert.deepEqual(
    setFindings(report.findings).map((f) => f.reason),
    [],
    'an intact ledger is not reported as tampered because of a non-matching pin',
  );
});

test('a legacy pin whose fingerprint equals the anchor logID still authenticates it', async () => {
  const { ledgerDir, rekor } = buildAnchoredLedger({ calls: 1 });

  assert.equal(getSpkiFingerprint(rekor.publicPem), rekor.logId);
  hostHasOnlyLegacyPin(rekor.publicPem);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, 'the matching pin authenticates the anchor');
  assert.deepEqual(setFindings(report.findings).map((f) => f.reason), []);
});
