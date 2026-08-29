// Tests for `attestor export --format cef` and `--format ocsf`
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAnchoredLedger } from './helpers.ts';
import { exportCef, exportOcsf } from '../src/export.ts';

test('export --format cef outputs valid Common Event Format records with ledger index fields', () => {
  const { dir, ledgerDir } = buildAnchoredLedger({ calls: 3 });
  const cef = exportCef(ledgerDir);

  assert.ok(cef.length > 0);
  const lines = cef.trim().split('\n');
  assert.equal(lines.length, 3);

  for (const line of lines) {
    assert.match(line, /^CEF:0\|attestor\|attestor\|0\.1\.0\|tool_call\|/);
    assert.match(line, /cs1Label=CallID/);
    assert.match(line, /cs2Label=LedgerEntryHash/);
    assert.match(line, /cn1Label=LedgerSeq/);
    assert.match(line, /cn3Label=RekorLogIndex/);
  }
});

test('export --format ocsf outputs valid OCSF API Activity JSONL records with unmapped index fields', () => {
  const { dir, ledgerDir } = buildAnchoredLedger({ calls: 2 });
  const ocsf = exportOcsf(ledgerDir);

  assert.ok(ocsf.length > 0);
  const lines = ocsf.trim().split('\n');
  assert.equal(lines.length, 2);

  for (const line of lines) {
    const record = JSON.parse(line) as any;
    assert.equal(record.class_uid, 6003);
    assert.equal(record.class_name, 'API Activity');
    assert.equal(record.category_uid, 6);
    assert.ok(record.unmapped);
    assert.ok(record.unmapped.ledger_seq !== undefined);
    assert.ok(record.unmapped.entry_hash !== undefined);
    assert.ok(record.unmapped.rekor_log_index !== undefined);
  }
});
