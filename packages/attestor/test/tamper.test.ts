// Tamper matrix: every attack must exit 1 with the correct blast radius;
// redaction must still PASS. Runs the full offline pipeline including ANCHOR
// checks against a simulated Rekor (fake log key pinned at anchors/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, unlinkSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import { verifyLedger } from '../src/verify.ts';
import { coreOf, canonicalCoreBytes, hashCore, signCore, genesisPrev, payloadHash, Ledger, type LedgerEntry } from '../src/ledger.ts';
import { buildPack } from '../src/export.ts';
import { keyIdOf, generateKey } from '../src/keys.ts';
import { hashedRekordBody, isOfficialSigstoreHost, verifyRekorKeyTrust, UntrustedRekorKeyError } from '../src/rekor.ts';
import { leafHash, merkleRoot } from '../src/merkle.ts';
import { writeCheckpoint } from '../src/checkpoint.ts';
import { buildAnchoredLedger, fakeRekor, fakeAnchor, rekorEntryFor, tmp } from './helpers.ts';

function readLines(ledgerDir: string): string[] {
  return readFileSync(join(ledgerDir, 'ledger.jsonl'), 'utf8').trimEnd().split('\n');
}

function writeLines(ledgerDir: string, lines: string[]): void {
  writeFileSync(join(ledgerDir, 'ledger.jsonl'), lines.join('\n') + '\n');
}

test('pristine anchored ledger verifies: exit 0', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
  assert.equal(report.result, 'VERIFIED');
  assert.ok(report.checks.find((c) => c.name === 'ANCHOR')?.ok);
});

test('core-field mutation: exit 1, blast radius from tampered entry', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const e = JSON.parse(lines[7]!) as LedgerEntry;
  e.ts = '1999-01-01T00:00:00.000Z'; // rewrite history
  lines[7] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.equal(report.result, 'TAMPER DETECTED');
  assert.equal(report.blastRadius?.from, 7);
  assert.equal(report.blastRadius?.to, lines.length - 1);
  assert.ok(report.findings.some((f) => f.check === 'CHAIN' && f.seq === 7));
  assert.ok(report.auditPacket);
});

test('payload mutation (the demo attack): payload_hash catches it', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const idx = lines.findIndex((l) => l.includes('100.00'));
  lines[idx] = lines[idx]!.replace('100.00', '100000.00');
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(
    report.findings.some((f) => f.check === 'CHAIN' && f.reason.includes('payload')),
  );
});

test('deleted middle line: seq gap detected', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  lines.splice(5, 1);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(report.findings.some((f) => f.check === 'CHAIN' && f.reason.includes('seq')));
});

test('swapped lines: chain break detected', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  [lines[3], lines[4]] = [lines[4]!, lines[3]!];
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
});

test('post-anchor truncation: orphaned stored anchor detected offline', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  // attacker truncates the tail including checkpoint + anchor entries
  writeLines(ledgerDir, lines.slice(0, 6));

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(
    report.findings.some((f) => f.check === 'ANCHOR' && /truncat/i.test(f.reason)),
    JSON.stringify(report.findings),
  );
});

test('truncation into anchored region with checkpoint retained: MERKLE fails', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const kept = [...lines.slice(0, 4), ...lines.slice(-2)]; // keep ckpt+anchor, drop middle... broken chain too
  writeLines(ledgerDir, kept);
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
});

test('re-sign entry with a foreign key: SIG catches key_id + signature', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const attacker = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const e = JSON.parse(lines[2]!) as LedgerEntry;
  e.payload = JSON.stringify({ status: 'ok', duration_ms: 1 }); // attacker edit
  // attacker recomputes commitment, hash and re-signs with their own key
  const attackerKeyObj = attacker.publicKey;
  e.key_id = keyIdOf(attackerKeyObj);
  const core = coreOf(e as unknown as Record<string, unknown>);
  e.hash = hashCore(core);
  e.sig = signCore(core, attacker.privateKey);
  lines[2] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  // chain break at 3 (prev mismatch) is expected; the key mismatch at 2 must also be flagged
  assert.ok(report.findings.some((f) => f.check === 'SIG' && f.seq === 2));
});

test('full rewrite + re-sign with attacker key, anchors kept: ANCHOR catches offline', async () => {
  const { ledgerDir, ledgerId } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const entries = lines.map((l) => JSON.parse(l) as LedgerEntry);
  // attacker generates their own recorder key and rewrites EVERYTHING,
  // including genesis (their pubkey) — self-consistent chain + sigs
  const atk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const atkPem = atk.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const atkKeyId = keyIdOf(atk.publicKey);
  let prev = genesisPrev(ledgerId);
  const rewritten: string[] = [];
  const newHashes: string[] = [];
  for (const e of entries) {
    if (e.type === 'genesis') {
      e.payload = JSON.stringify({ ledger_id: ledgerId, public_key_pem: atkPem, attestor_version: 1 });
    }
    if (e.payload?.includes('100.00')) {
      e.payload = e.payload.replace('100.00', '100000.00');
    }
    if (e.type === 'checkpoint') {
      // attacker recomputes the checkpoint root over rewritten entries
      const payload = JSON.parse(e.payload!) as { ledger_id: string; tree_size: number; root: string };
      const { merkleRoot } = await import('../src/merkle.ts');
      payload.root = merkleRoot(newHashes.slice(0, payload.tree_size).map((h) => Buffer.from(h, 'hex'))).toString('hex');
      e.payload = JSON.stringify(payload);
    }
    e.key_id = atkKeyId;
    e.prev = prev;
    const { createHash: ch } = await import('node:crypto');
    e.salt = ch('sha256').update(e.hash).digest('hex').slice(0, 32); // deterministic new salt
    e.payload_hash = (await import('../src/ledger.ts')).payloadHash(e.salt, e.payload);
    const core = coreOf(e as unknown as Record<string, unknown>);
    e.hash = hashCore(core);
    e.sig = signCore(core, atk.privateKey);
    prev = e.hash;
    newHashes.push(e.hash);
    rewritten.push(JSON.stringify(e));
  }
  writeLines(ledgerDir, rewritten);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  // CHAIN, MERKLE, SIG all pass — only the anchor gives the attacker away
  assert.ok(report.checks.find((c) => c.name === 'CHAIN')?.ok, 'attacker chain is self-consistent');
  assert.ok(report.checks.find((c) => c.name === 'SIG')?.ok, 'attacker sigs are self-consistent');
  assert.ok(
    report.findings.some((f) => f.check === 'ANCHOR' && f.reason.includes('anchored')),
    JSON.stringify(report.findings),
  );
});

test('forged anchor file (attacker fake Rekor key): SET verification fails', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  // attacker regenerates the stored anchor with their own "Rekor" key but
  // cannot replace the pinned log key (auditor cross-checks it)
  const lines = readLines(ledgerDir);
  const anchor = lines.map((l) => JSON.parse(l) as LedgerEntry).find((e) => e.type === 'anchor')!;
  const ckptSeq = (JSON.parse(anchor.payload!) as { checkpoint_seq: number }).checkpoint_seq;
  const stored = JSON.parse(readFileSync(join(ledgerDir, 'anchors', `${ckptSeq}.json`), 'utf8'));
  const fake = fakeRekor();
  const setCanon = canonicalize({
    body: stored.body,
    integratedTime: stored.integratedTime,
    logID: stored.logID,
    logIndex: stored.logIndex,
  })!;
  stored.verification.signedEntryTimestamp = cryptoSign(
    'sha256',
    Buffer.from(setCanon, 'utf8'),
    fake.privateKey,
  ).toString('base64');
  writeFileSync(join(ledgerDir, 'anchors', `${ckptSeq}.json`), JSON.stringify(stored));

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(report.findings.some((f) => f.check === 'ANCHOR' && f.reason.includes('SET')));
});

test('redacted entry still verifies: exit 0', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const idx = lines.findIndex((l) => l.includes('100.00'));
  const e = JSON.parse(lines[idx]!) as LedgerEntry;
  delete e.payload; // redaction drops the unsigned payload, nothing else
  lines[idx] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
  assert.ok(report.checks.find((c) => c.name === 'CHAIN')?.lines[0]?.includes('redacted'));
});

test('anchor lag reported for entries after last anchored checkpoint', async () => {
  const { ledgerDir, keys } = buildAnchoredLedger();
  const { Ledger } = await import('../src/ledger.ts');
  const ledger = Ledger.open(ledgerDir, keys);
  ledger.append({ type: 'wire', origin: 'proxy', payload: '"post-anchor traffic"' });
  ledger.close();

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0);
  assert.ok(report.anchorLag);
  assert.ok(report.anchorLag!.count >= 1);
});

test('--entry SEQ: inclusion path to nearest covering (anchored) checkpoint', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const report = await verifyLedger(ledgerDir, { entry: 3 });
  assert.equal(report.exitCode, 0);
  assert.ok(report.entryFocus);
  assert.equal(report.entryFocus!.seq, 3);
  assert.equal(report.entryFocus!.ok, true);
  assert.equal(report.entryFocus!.anchored, true);
  assert.ok(report.entryFocus!.proofLength! >= 1);
});

test('--entry SEQ on a tampered entry reports inclusion failure', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const e = JSON.parse(lines[3]!) as LedgerEntry;
  e.ts = '1999-01-01T00:00:00.000Z';
  lines[3] = JSON.stringify(e);
  writeLines(ledgerDir, lines);
  const report = await verifyLedger(ledgerDir, { entry: 3 });
  assert.equal(report.exitCode, 1);
  assert.equal(report.entryFocus!.ok, false);
});

test('--entry SEQ out of range is reported, not crashed', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const report = await verifyLedger(ledgerDir, { entry: 9999 });
  assert.ok(report.entryFocus);
  assert.equal(report.entryFocus!.ok, false);
  assert.ok(report.entryFocus!.note.includes('out of range'));
});

test('missing anchor file for anchor entry: fails', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const anchor = lines.map((l) => JSON.parse(l) as LedgerEntry).find((e) => e.type === 'anchor')!;
  const ckptSeq = (JSON.parse(anchor.payload!) as { checkpoint_seq: number }).checkpoint_seq;
  unlinkSync(join(ledgerDir, 'anchors', `${ckptSeq}.json`));

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
});

test('rewrite history + delete ONLY the anchor entry (keep the anchor file): caught', async () => {
  const { ledgerDir, ledgerId } = buildAnchoredLedger();
  const entries = readLines(ledgerDir).map((l) => JSON.parse(l) as LedgerEntry);
  const atk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const atkPem = atk.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const atkKeyId = keyIdOf(atk.publicKey);

  // Attacker rewrites every entry self-consistently and drops the `anchor`
  // entry, hoping verify reports "no anchors recorded" instead of failing.
  let prev = genesisPrev(ledgerId);
  const rewritten: string[] = [];
  const newHashes: string[] = [];
  for (const e of entries) {
    if (e.type === 'anchor') continue;
    if (e.type === 'genesis') {
      e.payload = JSON.stringify({ ledger_id: ledgerId, public_key_pem: atkPem, attestor_version: 1 });
    }
    if (e.payload?.includes('100.00')) e.payload = e.payload.replace('100.00', '100000.00');
    if (e.type === 'checkpoint') {
      const p = JSON.parse(e.payload!) as { ledger_id: string; tree_size: number; root: string };
      p.root = merkleRoot(newHashes.slice(0, p.tree_size).map((h) => Buffer.from(h, 'hex'))).toString('hex');
      e.payload = JSON.stringify(p);
    }
    e.key_id = atkKeyId;
    e.prev = prev;
    e.salt = createHash('sha256').update(e.hash).digest('hex').slice(0, 32);
    e.payload_hash = payloadHash(e.salt, e.payload);
    const core = coreOf(e as unknown as Record<string, unknown>);
    e.hash = hashCore(core);
    e.sig = signCore(core, atk.privateKey);
    prev = e.hash;
    newHashes.push(e.hash);
    rewritten.push(JSON.stringify(e));
  }
  writeLines(ledgerDir, rewritten);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1, 'deleting the anchor entry must NOT downgrade to "no anchors recorded"');
  assert.ok(
    report.findings.some((f) => f.check === 'ANCHOR'),
    JSON.stringify(report.findings),
  );
});

test('delete the anchor entry from an otherwise pristine ledger: still caught', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  writeLines(
    ledgerDir,
    lines.filter((l) => !(JSON.parse(l) as LedgerEntry).payload?.includes('"provider":"rekor-v1"')),
  );
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.ok(report.findings.some((f) => f.check === 'ANCHOR' && /no .*anchor. entry|deleted/.test(f.reason)));
});

test('anchors verifiable only by the artifact-shipped key do NOT exit 0', async () => {
  const { ledgerDir, dir } = buildAnchoredLedger();
  // An auditor on a fresh machine: no pinned Rekor key of their own. The pack
  // ships one, but a key travelling with the artifact cannot authenticate it.
  process.env.ATTESTOR_HOME = join(dir, 'no-pin');

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 4, 'must not report success for an unauthenticated anchor');
  assert.equal(report.result, 'ANCHORS UNAUTHENTICATED');
  assert.ok(report.checks.find((c) => c.name === 'ANCHOR')?.warn);
  assert.ok(report.findings.length === 0, 'this is not tamper — the chain itself is fine');
});

test('a fully forged pack (attacker recorder key AND attacker log key) never exits 0', async () => {
  const { ledgerDir, dir, ledgerId } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const entries = lines.map((l) => JSON.parse(l) as LedgerEntry);

  // The attacker controls everything shipped in the artifact: they rewrite and
  // re-sign the ledger with their own recorder key, forge the anchor over the
  // rewritten checkpoint, and ship their own "Rekor" key to validate it.
  const atk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const atkPem = atk.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const fakeLog = fakeRekor();

  let prev = genesisPrev(ledgerId);
  const newHashes: string[] = [];
  const rewritten: string[] = [];
  let ckpt: LedgerEntry | undefined;
  for (const e of entries) {
    if (e.type === 'genesis') {
      e.payload = JSON.stringify({ ledger_id: ledgerId, public_key_pem: atkPem, attestor_version: 1 });
    }
    if (e.payload?.includes('100.00')) e.payload = e.payload.replace('100.00', '100000.00');
    if (e.type === 'checkpoint') {
      const p = JSON.parse(e.payload!) as { ledger_id: string; tree_size: number; root: string };
      p.root = merkleRoot(newHashes.slice(0, p.tree_size).map((h) => Buffer.from(h, 'hex'))).toString('hex');
      e.payload = JSON.stringify(p);
    }
    e.key_id = keyIdOf(atk.publicKey);
    e.prev = prev;
    e.salt = createHash('sha256').update(e.hash).digest('hex').slice(0, 32);
    e.payload_hash = payloadHash(e.salt, e.payload);
    const core = coreOf(e as unknown as Record<string, unknown>);
    e.hash = hashCore(core);
    e.sig = signCore(core, atk.privateKey);
    prev = e.hash;
    newHashes.push(e.hash);
    rewritten.push(JSON.stringify(e));
    if (e.type === 'checkpoint') ckpt = JSON.parse(JSON.stringify(e)) as LedgerEntry;
  }
  writeLines(ledgerDir, rewritten);

  // forge the stored anchor over the rewritten checkpoint, signed by the fake log
  const artifact = canonicalCoreBytes(coreOf(ckpt as unknown as Record<string, unknown>));
  const forged = rekorEntryFor(fakeLog, hashedRekordBody(artifact, { ...({} as never), privateKey: atk.privateKey, publicPem: atkPem }));
  writeFileSync(join(ledgerDir, 'anchors', `${ckpt!.seq}.json`), JSON.stringify(forged, null, 2));
  writeFileSync(join(ledgerDir, 'anchors', 'rekor-pub.pem'), fakeLog.publicPem);

  // auditor has no pin of their own — everything they could check with came
  // from the attacker
  process.env.ATTESTOR_HOME = join(dir, 'no-pin');
  const report = await verifyLedger(ledgerDir);
  assert.notEqual(report.exitCode, 0, 'a forged pack must never report success');
  assert.equal(report.exitCode, 4);
});

test('salt-boundary slide: payload erased into the salt is caught', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const idx = lines.findIndex((l) => l.includes('100.00'));
  const e = JSON.parse(lines[idx]!) as LedgerEntry;

  // payload_hash is SHA256(salt‖payload) with no length prefix, and salt is
  // unsigned so redaction can drop it. Absorbing the payload into the salt
  // keeps the commitment valid while erasing the recorded content.
  const slid = Buffer.concat([Buffer.from(e.salt!, 'hex'), Buffer.from(e.payload!, 'utf8')]).toString('hex');
  const original = e.payload;
  e.salt = slid;
  e.payload = '';
  assert.equal(payloadHash(e.salt, e.payload), e.payload_hash, 'the commitment still matches — that is the trap');
  lines[idx] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1, `payload "${original}" was erased and verification passed`);
  assert.ok(report.findings.some((f) => /malformed salt/.test(f.reason)), JSON.stringify(report.findings));
});

test('partial slide (front-truncating a payload) is caught too', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  const lines = readLines(ledgerDir);
  const idx = lines.findIndex((l) => l.includes('100.00'));
  const e = JSON.parse(lines[idx]!) as LedgerEntry;
  const bytes = Buffer.from(e.payload!, 'utf8');
  e.salt = Buffer.concat([Buffer.from(e.salt!, 'hex'), bytes.subarray(0, 10)]).toString('hex');
  e.payload = bytes.subarray(10).toString('utf8');
  lines[idx] = JSON.stringify(e);
  writeLines(ledgerDir, lines);

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
});

test('deleting every anchor is not cheaper than forging one', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  // attacker removes the anchor entry AND the stored Rekor record, hoping the
  // ledger reads as "never anchored" rather than "anchors removed"
  const lines = readLines(ledgerDir).filter(
    (l) => !(JSON.parse(l) as LedgerEntry).payload?.includes('"provider":"rekor-v1"'),
  );
  writeLines(ledgerDir, lines);
  for (const f of readdirSync(join(ledgerDir, 'anchors'))) {
    if (/^\d+\.json$/.test(f)) unlinkSync(join(ledgerDir, 'anchors', f));
  }

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1, 'a pinned log key with zero anchors must not read as never-anchored');
  assert.ok(report.findings.some((f) => /no anchor entries/.test(f.reason)), JSON.stringify(report.findings));
});

test('a pack whose manifest claims anchors the ledger lacks is caught', async () => {
  const { dir, ledgerDir } = buildAnchoredLedger();
  const packDir = join(dir, 'pack-claims');
  await buildPack(ledgerDir, packDir);
  // strip the anchor entry, the stored record, and the pinned key — the
  // manifest still advertises the anchor
  const lp = join(packDir, 'ledger', 'entries.jsonl');
  writeFileSync(
    lp,
    readFileSync(lp, 'utf8')
      .trimEnd()
      .split('\n')
      .filter((l) => !(JSON.parse(l) as LedgerEntry).payload?.includes('"provider":"rekor-v1"'))
      .join('\n') + '\n',
  );
  for (const f of readdirSync(join(packDir, 'anchors', 'rekor'))) {
    unlinkSync(join(packDir, 'anchors', 'rekor', f));
  }
  unlinkSync(join(packDir, 'keys', 'rekor-pub.pem'));

  const report = await verifyLedger(packDir);
  assert.equal(report.exitCode, 1, 'the manifest is evidence too');
  assert.ok(report.findings.some((f) => /manifest declares an anchor/.test(f.reason)));
});

test('an intact pack verifies via its ledger file path, not just its directory', async () => {
  const { dir, ledgerDir } = buildAnchoredLedger();
  const packDir = join(dir, 'pack-bypath');
  await buildPack(ledgerDir, packDir);
  const byDir = await verifyLedger(packDir);
  const byFile = await verifyLedger(join(packDir, 'ledger', 'entries.jsonl'));
  assert.equal(byDir.exitCode, 0, JSON.stringify(byDir.findings));
  assert.equal(byFile.exitCode, byDir.exitCode, JSON.stringify(byFile.findings));
});

test('a staged anchor from a crashed run is not mistaken for a deleted entry', async () => {
  const { ledgerDir } = buildAnchoredLedger();
  // what a crash mid-anchor leaves behind: the record staged, no entry yet
  writeFileSync(join(ledgerDir, 'anchors', '99.json.partial'), '{"uuid":"x"}');
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings));
});

test('--expect-key binds a ledger to a recorder identity the auditor knows', async () => {
  const { ledgerDir, keys } = buildAnchoredLedger();
  const right = await verifyLedger(ledgerDir, { expectKeyId: keys.keyId });
  assert.equal(right.exitCode, 0, JSON.stringify(right.findings));

  // A fresh-key rewrite is internally consistent — only a known identity catches it.
  const wrong = await verifyLedger(ledgerDir, { expectKeyId: 'ff'.repeat(8) });
  assert.equal(wrong.exitCode, 1);
  assert.ok(wrong.findings.some((f) => /different key than expected/.test(f.reason)));

  // a PEM works as well as a key id
  const byPem = await verifyLedger(ledgerDir, { expectKeyId: keys.publicPem });
  assert.equal(byPem.exitCode, 0, JSON.stringify(byPem.findings));
});

// ---- integratedTime cross-check ------------------------------------------
// All four cases below are SELF-CONSISTENT: entries are written through the
// real append path and the anchor's SET is signed over the (possibly shifted)
// integratedTime, so CHAIN/MERKLE/SIG stay green and only the time policy is
// exercised.

function timeShiftedLedger(integratedTimeShiftSec: number): { dir: string; ledgerDir: string; keys: ReturnType<typeof generateKey>; ledger: Ledger; rekor: ReturnType<typeof fakeRekor> } {
  const dir = tmp();
  const ledgerDir = join(dir, 'ledger');
  process.env.ATTESTOR_HOME = join(dir, 'home');
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(ledgerDir, keys);
  const rekor = fakeRekor();
  ledger.append({
    type: 'call_request',
    origin: 'proxy',
    call_id: 'call-t',
    tool: { server: 'toy', name: 'echo' },
    payload: JSON.stringify({ text: 'hello' }),
  });
  const ckpt = writeCheckpoint(ledger);
  fakeAnchor(ledger, ckpt, rekor, { integratedTime: Math.floor(Date.now() / 1000) + integratedTimeShiftSec });
  return { dir, ledgerDir, keys, ledger, rekor };
}

test('long-delay attack: covered entry ts beyond integratedTime skew, authenticated anchor: exit 1', async () => {
  // The log claims it integrated the checkpoint an hour BEFORE the covered
  // entry says it was written — impossible with honest clocks.
  const { ledgerDir, ledger } = timeShiftedLedger(-3600);
  ledger.close();
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1, JSON.stringify(report.findings, null, 2));
  assert.ok(report.findings.some((f) => f.check === 'ANCHOR' && /is later than covering Rekor anchor/.test(f.reason)));
  // Isolation: the time policy is the ONLY thing that fired.
  assert.ok(!report.findings.some((f) => f.check === 'CHAIN' || f.check === 'MERKLE' || f.check === 'SIG'));
});

test('integratedTime within the skew tolerance: exit 0 (no warning noise)', async () => {
  const { ledgerDir, ledger } = timeShiftedLedger(-60); // 60s < 300s tolerance
  ledger.close();
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
});

test('post-checkpoint entry with future ts is NOT inspected by the integratedTime check', async () => {
  // A future-dated entry AFTER the anchored checkpoint is outside the covered
  // prefix [0, tree_size): the anchor makes no claim about it (it lives in the
  // ANCHOR LAG region), so the time policy must stay silent.
  const { ledgerDir, keys, ledger } = timeShiftedLedger(0);
  ledger.append({
    type: 'call_request',
    origin: 'proxy',
    call_id: 'call-post',
    tool: { server: 'toy', name: 'echo' },
    payload: JSON.stringify({ text: 'after checkpoint' }),
  });
  ledger.close();
  // Shift the tail entry into the future and re-sign; it is the last line, so
  // no prev_hash references it and the chain stays intact.
  const lines = readLines(ledgerDir);
  const e = JSON.parse(lines[lines.length - 1]!) as LedgerEntry;
  e.ts = '2035-01-01T00:00:00.000Z';
  e.hash = hashCore(e);
  e.sig = signCore(e, keys.privateKey);
  lines[lines.length - 1] = JSON.stringify(e);
  writeLines(ledgerDir, lines);
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
  assert.ok(!report.findings.some((f) => /integratedTime/.test(f.reason)));
});

test('unauthenticated anchor with a violating integratedTime: exit 4, never tamper', async () => {
  // Same long-delay ledger, but the auditor has no independently trusted log
  // key: integratedTime is attacker-controlled metadata and must not be able
  // to mint an exit-1 verdict. Exit 4 semantics are preserved.
  const { dir, ledgerDir, ledger } = timeShiftedLedger(-3600);
  ledger.close();
  rmSync(join(dir, 'home', 'keys', 'rekor-pub.pem'));
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 4, JSON.stringify(report.findings, null, 2));
  assert.ok(!report.findings.some((f) => /is later than covering Rekor anchor/.test(f.reason)));
});


test('adversary rotation injection signed by unauthorized key: exit 1 with SIG finding', async () => {
  const { ledgerDir } = buildAnchoredLedger({ calls: 2 });
  const home = process.env.ATTESTOR_HOME!;

  const attackerKeys = generateKey(home);
  const nextKeys = generateKey(home);

  // Attacker appends key_rotation signed with their own key, not the active
  // recorder key: the rotation must not take effect and must read as tamper.
  const ledgerAttacker = Ledger.open(ledgerDir, attackerKeys);
  ledgerAttacker.append({
    type: 'key_rotation',
    origin: 'system',
    payload: nextKeys.publicPem,
  });
  ledgerAttacker.close();

  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1);
  assert.equal(report.result, 'TAMPER DETECTED');
  assert.ok(report.findings.some((f) => f.check === 'SIG'), JSON.stringify(report.findings, null, 2));
});

// ---- Rekor trust-root allowlist attacks ----------------------------------

/** Anchored ledger whose anchor entry CLAIMS `url`, authenticated by the fake log key (pinned). */
function anchoredLedgerClaiming(url: string): string {
  const dir = tmp();
  const ledgerDir = join(dir, 'ledger');
  process.env.ATTESTOR_HOME = join(dir, 'home');
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(ledgerDir, keys);
  ledger.append({
    type: 'call_request',
    origin: 'proxy',
    call_id: 'call-0',
    tool: { server: 'toy', name: 'echo' },
    payload: JSON.stringify({ text: 'hello' }),
  });
  const ckpt = writeCheckpoint(ledger);
  fakeAnchor(ledger, ckpt, fakeRekor(), { url });
  ledger.close();
  return ledgerDir;
}

test('legacy-pin attack: rogue pin authenticating an anchor that claims the official log: exit 1', async () => {
  // A TOFU-era pin (here: the fake log key, pinned at both anchors/ and the
  // home dir) is NOT Sigstore's key. An anchor claiming rekor.sigstore.dev
  // that only such a pin can authenticate is forged evidence, not merely
  // unauthenticated.
  const ledgerDir = anchoredLedgerClaiming('https://rekor.sigstore.dev');
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1, JSON.stringify(report.findings, null, 2));
  assert.ok(report.findings.some((f) => f.check === 'ANCHOR' && /not Sigstore/.test(f.reason)));
});

test('URL-spelling attack: uppercase official host spelling does not bypass the gate', async () => {
  const ledgerDir = anchoredLedgerClaiming('HTTPS://REKOR.SIGSTORE.DEV/');
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 1, JSON.stringify(report.findings, null, 2));
  assert.ok(report.findings.some((f) => f.check === 'ANCHOR' && /not Sigstore/.test(f.reason)));
});

test('lookalike host is a custom log, not the official one: auditor-pinned key stands', async () => {
  // The substring match used to promote this to "official". It is not: it is
  // some other log the auditor pinned themselves, and the allowlist makes no
  // claim about it.
  const ledgerDir = anchoredLedgerClaiming('https://rekor.sigstore.dev.evil.example');
  const report = await verifyLedger(ledgerDir);
  assert.equal(report.exitCode, 0, JSON.stringify(report.findings, null, 2));
});

test('official-host detection is canonical, not raw string matching', () => {
  assert.ok(isOfficialSigstoreHost('https://rekor.sigstore.dev'));
  assert.ok(isOfficialSigstoreHost('HTTPS://REKOR.SIGSTORE.DEV'));
  assert.ok(isOfficialSigstoreHost('https://rekor.sigstore.dev/'));
  assert.ok(isOfficialSigstoreHost('https://rekor.sigstore.dev:443/api'));
  assert.ok(!isOfficialSigstoreHost('https://rekor.sigstore.dev.evil.example'));
  assert.ok(!isOfficialSigstoreHost('https://evil.example/?rekor.sigstore.dev'));
  assert.ok(!isOfficialSigstoreHost('not a url'));
  // and the gate itself follows the same canonicalization
  const rogue = fakeRekor().publicPem;
  assert.throws(() => verifyRekorKeyTrust('HTTPS://REKOR.SIGSTORE.DEV', rogue), UntrustedRekorKeyError);
  assert.doesNotThrow(() => verifyRekorKeyTrust('https://rekor.sigstore.dev.evil.example', rogue));
});
