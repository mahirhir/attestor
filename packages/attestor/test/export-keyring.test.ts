// An evidence pack has to carry every pinned log key, not just the legacy
// single-file pin. A ledger that spans a log-key rotation has anchors under
// two log IDs; if the export drops the keyed pins, a fresh auditor has no key
// for the rotated anchors and an honest pack reads as unverifiable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { attestorHome, keysDir } from '../src/keys.ts';
import { Ledger } from '../src/ledger.ts';
import { writeCheckpoint } from '../src/checkpoint.ts';
import { buildPack } from '../src/export.ts';
import { buildAnchoredLedger, fakeAnchor, fakeRekor } from './helpers.ts';

test('an exported pack carries every pinned log key, not only the legacy pin', async () => {
  // Anchor once under log A (buildAnchoredLedger), then again under log B:
  // the shape of a ledger that spans a log-key rotation.
  const { ledgerDir, keys } = buildAnchoredLedger({ calls: 1 });
  const logB = fakeRekor();
  const ledger = Ledger.open(ledgerDir, keys);
  ledger.append({
    type: 'call_request',
    origin: 'proxy',
    call_id: 'post-rotation',
    tool: { server: 'toy', name: 'echo' },
    payload: JSON.stringify({ text: 'after the log rotated' }),
  });
  const ckpt = writeCheckpoint(ledger);
  fakeAnchor(ledger, ckpt, logB);
  ledger.close();

  const hostPins = readdirSync(keysDir(attestorHome())).filter((f) => f.startsWith('rekor-pub'));
  assert.ok(
    hostPins.includes(`rekor-pub-${logB.logId}.pem`),
    'the second log key is pinned before export',
  );

  const out = join(mkdtempSync(join(tmpdir(), 'attestor-pack-')), 'pack');
  await buildPack(ledgerDir, out);

  const packed = readdirSync(join(out, 'keys')).filter((f) => f.startsWith('rekor-pub'));
  assert.ok(
    packed.includes(`rekor-pub-${logB.logId}.pem`),
    `the rotated log key is in the pack (packed: ${packed.join(', ')})`,
  );

  rmSync(out, { recursive: true, force: true });
});
