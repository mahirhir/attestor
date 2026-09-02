// Tests for key rotation and verification:
// - happy path rotation across active key changes
// - anchors generated for checkpoints created before rotation
// (the adversarial rotation-injection case lives in tamper.test.ts, per the
// repository's attack-matrix policy)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from '../src/keys.ts';
import { Ledger } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { writeCheckpoint } from '../src/checkpoint.ts';
import { buildAnchoredLedger, fakeAnchor } from './helpers.ts';

test('key rotation: entries before and after rotation verify cleanly', async () => {
  const { ledgerDir, keys: oldKeys, rekor } = buildAnchoredLedger({ calls: 2 });
  const home = process.env.ATTESTOR_HOME!;

  // 1. Generate new recorder key
  const newKeys = generateKey(home);

  // 2. Append key_rotation signed by old key
  const ledgerOld = Ledger.open(ledgerDir, oldKeys);
  ledgerOld.append({
    type: 'key_rotation',
    origin: 'system',
    payload: newKeys.publicPem,
  });
  ledgerOld.close();

  // 3. Append subsequent entries signed by new key
  const ledgerNew = Ledger.open(ledgerDir, newKeys);
  ledgerNew.append({
    type: 'call_request',
    origin: 'proxy',
    call_id: 'call-post-rotate-1',
    tool: { server: 'toy', name: 'post_rotate_action' },
    payload: JSON.stringify({ action: 'mutate' }),
  });
  ledgerNew.append({
    type: 'call_result',
    origin: 'proxy',
    call_id: 'call-post-rotate-1',
    payload: JSON.stringify({ status: 'ok' }),
  });

  const ckpt2 = writeCheckpoint(ledgerNew);
  fakeAnchor(ledgerNew, ckpt2, rekor);
  ledgerNew.close();

  // 4. Verify full ledger: valid rotation must exit 0
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
  assert.equal(report.result, 'VERIFIED');
  assert.ok(report.checks.find((c) => c.name === 'SIG')?.ok);
});

test('key rotation: anchor written after rotation for checkpoint created before rotation verifies', async () => {
  const { ledgerDir, keys: oldKeys, rekor } = buildAnchoredLedger({ calls: 2 });
  const home = process.env.ATTESTOR_HOME!;

  const ledgerOld = Ledger.open(ledgerDir, oldKeys);
  const preCkpt = writeCheckpoint(ledgerOld);

  const newKeys = generateKey(home);
  ledgerOld.append({
    type: 'key_rotation',
    origin: 'system',
    payload: newKeys.publicPem,
  });
  ledgerOld.close();

  // Open with new keys and anchor the pre-rotation checkpoint
  const ledgerNew = Ledger.open(ledgerDir, newKeys);
  fakeAnchor(ledgerNew, preCkpt, rekor);
  ledgerNew.close();

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
  assert.equal(report.result, 'VERIFIED');
});
