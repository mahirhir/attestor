// End to end for the rotation story: a ledger whose anchors span two log keys,
// exported, then verified by an auditor who has never seen either key. The
// pack's own keys are artifact-shipped (consistency, never authentication), so
// the honest outcome is "anchors unauthenticated", never "tamper".
//
// What this does NOT cover, deliberately stated: it does not discriminate
// whether the pack actually carries a key for every anchor. Dropping the keyed
// pins from the export produces byte-identical verify output, because an anchor
// with no available key and an anchor checked for consistency both land in the
// unauthenticated lane. That gap is a reporting defect rather than a gap in
// this test, and the pin-completeness property is asserted at file level in
// export-keyring.test.ts instead.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Ledger } from '../src/ledger.ts';
import { writeCheckpoint } from '../src/checkpoint.ts';
import { buildPack } from '../src/export.ts';
import { verifyLedger } from '../src/verify.ts';
import { buildAnchoredLedger, fakeAnchor, fakeRekor } from './helpers.ts';

test('a rotated ledger exports and verifies from a home that has never seen its log keys', async () => {
  const { ledgerDir, keys } = buildAnchoredLedger({ calls: 1 });
  const logB = fakeRekor();
  const ledger = Ledger.open(ledgerDir, keys);
  ledger.append({
    type: 'call_request',
    origin: 'proxy',
    call_id: 'after-rotation',
    tool: { server: 'toy', name: 'echo' },
    payload: JSON.stringify({ text: 'anchored under the rotated log key' }),
  });
  fakeAnchor(ledger, writeCheckpoint(ledger), logB);
  ledger.close();

  const packDir = join(mkdtempSync(join(tmpdir(), 'attestor-rot-')), 'pack');
  await buildPack(ledgerDir, packDir);

  // A fresh auditor: no pins, no history, nothing carried over from the
  // recorder's machine. Without this the host keyring answers every lookup and
  // the pack's own contents are never exercised.
  process.env.ATTESTOR_HOME = mkdtempSync(join(tmpdir(), 'attestor-fresh-home-'));

  const report = await verifyLedger(packDir);

  const tamper = report.findings.filter((f) => f.check === 'ANCHOR');
  assert.deepEqual(
    tamper.map((f) => f.reason),
    [],
    'an honest rotated pack produces no ANCHOR finding',
  );
  // 4 = chain intact, anchors present but only artifact-shipped keys available.
  // 1 would mean tamper; 0 would mean the pack authenticated itself, which it
  // must never be able to do.
  assert.equal(report.exitCode, 4, 'unauthenticated, not tampered and not self-authenticated');

  rmSync(packDir, { recursive: true, force: true });
});
