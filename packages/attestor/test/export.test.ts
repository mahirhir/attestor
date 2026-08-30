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

test('export --format ocsf: emits valid OCSF 1.3.0 records with anchor and ledger traceability', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const { exportOcsf } = await import('../src/export.ts');
  const ocsfOutput = exportOcsf(ledgerDir);
  assert.ok(ocsfOutput.length > 0, 'ocsf output should not be empty');

  const lines = ocsfOutput.trim().split('\n');
  assert.ok(lines.length >= 1, 'should have at least 1 tool call event');
  for (const line of lines) {
    const record = JSON.parse(line);
    assert.equal(record.class_uid, 6003);
    assert.equal(record.class_name, 'API Activity');
    assert.equal(record.category_uid, 6);
    assert.equal(record.metadata.version, '1.3.0');
    assert.equal(record.metadata.product.name, 'attestor');
    assert.ok(record.api.operation, 'operation tool name must exist');
    assert.ok(record.unmapped.ledger_seq_req !== undefined);
    assert.ok(record.unmapped.ledger_hash_req);
    assert.ok(record.unmapped.ledger_seq_res !== undefined);
    assert.ok(record.unmapped.ledger_hash_res);
    assert.ok(record.unmapped.audit_note.includes('tamper-evident ledger'));
  }
});

test('export --format cef: emits valid Common Event Format records with ledger fields', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const { exportCef } = await import('../src/export.ts');
  const cefOutput = exportCef(ledgerDir);
  assert.ok(cefOutput.length > 0, 'cef output should not be empty');

  const lines = cefOutput.trim().split('\n');
  assert.ok(lines.length >= 1, 'should have at least 1 tool call event');
  for (const line of lines) {
    assert.ok(line.startsWith('CEF:0|attestor|attestor|0.1.0|agent_tool_call|'));
    assert.ok(line.includes('cs1Label=ledgerSeqReq'));
    assert.ok(line.includes('cs2Label=ledgerHashReq'));
    assert.ok(line.includes('cs3Label=ledgerSeqRes'));
    assert.ok(line.includes('cs4Label=ledgerHashRes'));
    assert.ok(line.includes('suser='));
  }
});
