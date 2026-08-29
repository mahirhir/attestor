// Evidence pack: layout, manifest hashes, pack verifies via the same CLI
// path an auditor would use, redaction round-trip through export + redact.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildPack } from '../src/export.ts';
import { redactEntry } from '../src/redact.ts';
import { readEntries } from '../src/ledger.ts';
import { verifyLedger } from '../src/verify.ts';
import { buildAnchoredLedger } from './helpers.ts';

test('evidence pack: layout complete, manifest hashes every file, pack verifies', async () => {
  const { dir, ledgerDir } = buildAnchoredLedger();
  const packDir = join(dir, 'pack');
  await buildPack(ledgerDir, packDir);

  for (const f of [
    'manifest.json',
    'ledger/entries.jsonl',
    'keys/recorder-pub.pem',
    'keys/rekor-pub.pem',
    'controls/mapping.json',
    'VERIFY.md',
    'report.html',
  ]) {
    assert.ok(existsSync(join(packDir, f)), `missing ${f}`);
  }

  const manifest = JSON.parse(readFileSync(join(packDir, 'manifest.json'), 'utf8')) as {
    entry_count: number;
    verify_result_at_export: string;
    anchors: { uuid: string; log_index: number }[];
    files_sha256: Record<string, string>;
  };
  assert.equal(manifest.verify_result_at_export, 'VERIFIED');
  assert.equal(manifest.anchors.length, 1);
  assert.ok(manifest.files_sha256['ledger/entries.jsonl']);
  // manifest hashes are correct
  for (const [rel, expected] of Object.entries(manifest.files_sha256)) {
    if (rel === 'manifest.json') continue;
    const actual = createHash('sha256').update(readFileSync(join(packDir, rel))).digest('hex');
    assert.equal(actual, expected, `hash mismatch: ${rel}`);
  }

  // the pack itself verifies (pack layout: ledger/entries.jsonl + anchors/rekor/)
  const report = await verifyLedger(packDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));

  // VERIFY.md carries the pure curl/jq/openssl recipe with the real uuid
  const verifyMd = readFileSync(join(packDir, 'VERIFY.md'), 'utf8');
  assert.ok(verifyMd.includes(manifest.anchors[0]!.uuid));
  assert.ok(verifyMd.includes('openssl dgst -sha256 -verify'));
  assert.ok(verifyMd.includes('jq -cjS'));

  // control mappings stay honest
  const mapping = JSON.parse(readFileSync(join(packDir, 'controls', 'mapping.json'), 'utf8')) as { disclaimer: string };
  assert.ok(mapping.disclaimer.includes('assessor'));
});

test('redact → export → pack still verifies; payload gone, commitment kept', async () => {
  const { dir, ledgerDir } = buildAnchoredLedger();
  const before = readEntries(join(ledgerDir, 'ledger.jsonl'));
  const target = before.find((e) => e.payload?.includes('100.00'))!;
  const redacted = redactEntry(ledgerDir, target.seq);
  assert.equal(redacted.payload, undefined);
  assert.equal(redacted.payload_hash, target.payload_hash);

  const packDir = join(dir, 'pack-redacted');
  await buildPack(ledgerDir, packDir);
  const report = await verifyLedger(packDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
  const packLedger = readFileSync(join(packDir, 'ledger', 'entries.jsonl'), 'utf8');
  assert.ok(!packLedger.includes('100.00'), 'redacted amount must not appear anywhere in the pack ledger');
});

test('redact refuses system entries and double-redaction', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const entries = readEntries(join(ledgerDir, 'ledger.jsonl'));
  const ckpt = entries.find((e) => e.type === 'checkpoint')!;
  assert.throws(() => redactEntry(ledgerDir, ckpt.seq), /refusing to redact checkpoint/);
  assert.throws(() => redactEntry(ledgerDir, 0), /refusing to redact genesis/);
  const wire = entries.find((e) => e.type === 'call_request')!;
  redactEntry(ledgerDir, wire.seq);
  assert.throws(() => redactEntry(ledgerDir, wire.seq), /already redacted/);
});

test('redact appends in-chain redaction entry and verify reports attested', async () => {
  const { ledgerDir, keys } = buildAnchoredLedger();
  const before = readEntries(join(ledgerDir, 'ledger.jsonl'));
  const target = before.find((e) => e.payload?.includes('100.00'))!;
  redactEntry(ledgerDir, target.seq, { reason: 'GDPR right to be forgotten', keys });

  const after = readEntries(join(ledgerDir, 'ledger.jsonl'));
  const cert = after.find((e) => e.type === 'redaction');
  assert.ok(cert, 'in-chain redaction certificate must be recorded');
  const payload = JSON.parse(cert.payload!) as { target_seq: number; reason: string };
  assert.equal(payload.target_seq, target.seq);
  assert.equal(payload.reason, 'GDPR right to be forgotten');

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0);
  const chainLine = report.checks.find((c) => c.name === 'CHAIN')?.lines[0];
  assert.ok(chainLine?.includes('all in-chain attested'));
});
